/*
 * Copyright (C) 2026 SimbaDroid contributors
 *
 * This file is part of JFileServer.
 *
 * JFileServer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JFileServer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JFileServer. If not, see <http://www.gnu.org/licenses/>.
 */

package org.filesys.smb.server.smb2;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.filesys.debug.Debug;
import org.filesys.server.auth.ClientInfo;
import org.filesys.server.auth.ISMBAuthenticator;
import org.filesys.server.auth.SMBAuthenticator;
import org.filesys.server.auth.acl.AccessControl;
import org.filesys.server.auth.acl.AccessControlManager;
import org.filesys.server.core.InvalidDeviceInterfaceException;
import org.filesys.server.core.ShareType;
import org.filesys.server.core.SharedDevice;
import org.filesys.server.filesys.AccessDeniedException;
import org.filesys.server.filesys.DirectoryNotEmptyException;
import org.filesys.server.filesys.DiskDeviceContext;
import org.filesys.server.filesys.DiskFullException;
import org.filesys.server.filesys.DiskInterface;
import org.filesys.server.filesys.FileAccess;
import org.filesys.server.filesys.FileExistsException;
import org.filesys.server.filesys.FileNameException;
import org.filesys.server.filesys.FileSharingException;
import org.filesys.server.filesys.NetworkFile;
import org.filesys.server.filesys.PathNotFoundException;
import org.filesys.server.filesys.PermissionDeniedException;
import org.filesys.server.filesys.SrvDiskInfo;
import org.filesys.server.filesys.TooManyConnectionsException;
import org.filesys.server.filesys.TooManyFilesException;
import org.filesys.server.filesys.TreeConnection;
import org.filesys.server.filesys.VolumeInfo;
import org.filesys.smb.Dialect;
import org.filesys.smb.SMBStatus;
import org.filesys.smb.server.NegotiateContext;
import org.filesys.smb.server.Protocol;
import org.filesys.smb.server.ProtocolHandler;
import org.filesys.smb.server.SMBConfigSection;
import org.filesys.smb.server.SMBPacketPool;
import org.filesys.smb.server.SMBServer;
import org.filesys.smb.server.SMBSrvException;
import org.filesys.smb.server.SMBSrvPacket;
import org.filesys.smb.server.SMBSrvSession;
import org.filesys.smb.server.VirtualCircuit;
import org.filesys.smb.server.VirtualCircuitList;
import org.filesys.smb.server.SMBV1VirtualCircuitList;

/**
 * SMB2/SMB3 protocol handler.
 *
 * <p>Implements the SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1 dialects on top of the existing JFileServer session,
 * share and filesystem driver model. One handler instance exists per client connection and holds the connection
 * state: the negotiated dialect and capabilities, the authenticated sessions and the outstanding asynchronous
 * requests.
 *
 * <p>This class deals with the connection level parts of the protocol - negotiation, request framing (including
 * compounded requests), credits, signing, encryption, session setup and tree connects. The file level commands
 * are implemented by {@link SMB2FileOperations}, {@link SMB2InfoOperations} and {@link SMB2IoctlOperations}.
 */
public class SMB2ProtocolHandler extends ProtocolHandler {

    // Offset of the first SMB2 message within a packet buffer, after the 4 byte transport header
    static final int HDR = 4;

    // Maximum number of credits a connection may hold, the same limit as Windows and Samba use
    private static final int MAX_CREDITS = 8192;

    // Maximum number of authenticated sessions per connection
    private static final int MAX_SESSIONS = 32;

    // Maximum number of asynchronous requests that may be outstanding on a connection
    private static final int MAX_PENDING_REQUESTS = 64;

    // I/O size limits, the smaller value is used for SMB 2.0.2 which does not have multi-credit requests
    static final int MIN_IO_SIZE = 64 * 1024;
    private static final int MAX_IO_SIZE = 1024 * 1024;

    // Headroom to leave in a packet buffer for the request headers and an encryption transform header
    private static final int IO_HEADROOM = 512;

    private static final int NEG_RESPONSE_BUFSIZE = 1024;
    private static final int NEG_RESPONSE_FIXED = 64;

    private static final int PREAUTH_HASH_LEN = 64;
    private static final int PREAUTH_SALT_LEN = 32;

    // Internal status values returned by command handlers
    static final int STS_NO_RESPONSE = 0x7FFFFFFE;

    private static final long NT_TIME_OFFSET = 116444736000000000L;

    private static final AtomicLong s_sessionIds = new AtomicLong((SMB2Crypto.randomLong() & 0x3FFFFFFFL) + 0x10000L);

    private static final long s_serverStartTime = toNTTime(System.currentTimeMillis());

    /**
     * An asynchronous request that has been acknowledged with an interim response and is waiting to be completed
     */
    static final class PendingRequest {
        final long asyncId;
        final long messageId;
        final int command;
        final SMB2Session session;
        final SMB2Open open;
        final boolean signed;
        final boolean encrypted;
        final int outputLength;

        private final AtomicBoolean m_completed = new AtomicBoolean();

        PendingRequest(long asyncId, SMB2Request req, SMB2Open open, int outputLength) {
            this.asyncId = asyncId;
            this.messageId = req.messageId();
            this.command = req.command();
            this.session = req.session;
            this.open = open;
            this.signed = req.signed;
            this.encrypted = req.isEncrypted();
            this.outputLength = outputLength;
        }
    }

    /**
     * Details of a response that has been built, used to finalize the responses of a compound once they are all known
     */
    private static final class ResponseInfo {
        final int hdrPos;
        final SMB2Session signSession;
        final SMB2Session preauthSession;

        ResponseInfo(int hdrPos, SMB2Session signSession, SMB2Session preauthSession) {
            this.hdrPos = hdrPos;
            this.signSession = signSession;
            this.preauthSession = preauthSession;
        }
    }

    /**
     * State carried between the requests of a compound chain
     */
    private static final class Chain {
        boolean first = true;
        long sessionId;
        int treeId;
        long fileId = SMB2Request.RELATED_ID;
        int createError;
    }

    // Negotiated connection state
    private volatile int m_dialectRev;
    private byte[] m_clientGuid = new byte[16];
    private int m_clientSecMode;
    private int m_clientCaps;
    private int m_serverCaps;
    private int m_serverSecMode;
    private int m_cipherId = SMB2.CIPHER_NONE;
    private byte[] m_preauthHash;
    private int m_maxIoSize = MIN_IO_SIZE;

    private boolean m_signingRequired;
    private boolean m_encryptionRequired;

    // Details of the negotiate request, saved until the response is built
    private long m_negMessageId;
    private int m_negCreditRequest;
    private byte[] m_negRequestHash;

    private final Object m_creditLock = new Object();
    private int m_credits = 1;

    private final ConcurrentHashMap<Long, SMB2Session> m_sessions = new ConcurrentHashMap<Long, SMB2Session>();
    private final ConcurrentHashMap<Long, PendingRequest> m_pending = new ConcurrentHashMap<Long, PendingRequest>();

    private final AtomicLong m_fileIds = new AtomicLong((SMB2Crypto.randomLong() & 0x3FFFFFFFL) + 1);
    private final AtomicLong m_asyncIds = new AtomicLong(1);

    private final SMB2FileOperations m_fileOps = new SMB2FileOperations(this);
    private final SMB2InfoOperations m_infoOps = new SMB2InfoOperations(this);
    private final SMB2IoctlOperations m_ioctlOps = new SMB2IoctlOperations(this);

    /**
     * Default constructor, used by the protocol factory
     */
    public SMB2ProtocolHandler() {
    }

    @Override
    public String getName() {
        return "SMB2";
    }

    @Override
    public VirtualCircuitList createVirtualCircuitList(int maxVC) {
        return new SMBV1VirtualCircuitList(maxVC);
    }

    // Accessors for the command handler classes

    final SMBSrvSession sess() {
        return m_sess;
    }

    final int dialectRevision() {
        return m_dialectRev;
    }

    final int maxIoSize() {
        return m_maxIoSize;
    }

    final byte[] clientGuid() {
        return m_clientGuid;
    }

    final int serverCapabilities() {
        return m_serverCaps;
    }

    final int serverSecurityMode() {
        return m_serverSecMode;
    }

    final SMB2IoctlOperations ioctlOperations() {
        return m_ioctlOps;
    }

    /**
     * Check if there are any files or directories open below a directory, on this connection
     *
     * @param tree    TreeConnection
     * @param dirPath String
     * @return boolean
     */
    final boolean hasOpensBelow(TreeConnection tree, String dirPath) {
        String prefix = dirPath + "\\";

        for (SMB2Session session : m_sessions.values()) {
            for (SMB2Open open : session.opens.values()) {
                if (!open.isPipe() && open.getTree().getSharedDevice() == tree.getSharedDevice()
                        && open.getPath().regionMatches(true, 0, prefix, 0, prefix.length()))
                    return true;
            }
        }
        return false;
    }

    final boolean hasDebug(SMBSrvSession.Dbg flag) {
        return Debug.EnableInfo && m_sess.hasDebug(flag);
    }

    final void debug(String msg) {
        m_sess.debugPrintln("[SMB2] " + msg);
    }

    static long toNTTime(long javaTime) {
        return javaTime <= 0 ? 0 : (javaTime * 10000L) + NT_TIME_OFFSET;
    }

    static long fromNTTime(long ntTime) {
        return (ntTime - NT_TIME_OFFSET) / 10000L;
    }

    /**
     * Return the disk interface for a tree connection
     *
     * @param tree TreeConnection
     * @return DiskInterface
     * @exception SMB2Exception Not a disk share
     */
    final DiskInterface diskInterface(TreeConnection tree)
            throws SMB2Exception {
        try {
            if (tree.getSharedDevice().getType() == ShareType.DISK && tree.getSharedDevice().getInterface() instanceof DiskInterface)
                return (DiskInterface) tree.getSharedDevice().getInterface();
        }
        catch (InvalidDeviceInterfaceException ex) {
            // Fall through
        }
        throw new SMB2Exception(SMB2.STATUS_INVALID_DEVICE_REQUEST);
    }

    final SrvDiskInfo diskInformation(DiskInterface disk, DiskDeviceContext ctx)
            throws IOException {
        return getDiskInformation(disk, ctx);
    }

    final VolumeInfo volumeInformation(DiskInterface disk, DiskDeviceContext ctx) {
        return getVolumeInformation(disk, ctx);
    }

    //-------------------------------------------------------------------------------------------------------------
    // Negotiate
    //-------------------------------------------------------------------------------------------------------------

    /**
     * Called by the session once this handler has been selected for the negotiated dialect, to allocate the packet
     * that the negotiate response will be built in.
     */
    @Override
    public SMBSrvPacket postProcessNegotiate(SMBSrvPacket smbPkt, NegotiateContext negCtx)
            throws SMBSrvException {

        m_negMessageId = 0;
        m_negCreditRequest = 1;
        m_negRequestHash = null;

        if (smbPkt.isSMB2()) {
            byte[] buf = smbPkt.getBuffer();
            int len = smbPkt.getReceivedLength() - HDR;

            m_negMessageId = SMB2Buf.getLong(buf, HDR + SMB2.OFF_MESSAGE_ID);
            m_negCreditRequest = SMB2Buf.getShort(buf, HDR + SMB2.OFF_CREDITS);

            // Start the pre-authentication integrity hash with the negotiate request
            try {
                m_negRequestHash = SMB2Crypto.updatePreauthHash(new byte[PREAUTH_HASH_LEN], buf, HDR, len);
            }
            catch (GeneralSecurityException ex) {
                throw new SMBSrvException(SMBStatus.NTInvalidParameter, ex);
            }
        }

        // The response is always an SMB2 packet, even if the request was an SMB1 multi-protocol negotiate
        byte[] respBuf = new byte[NEG_RESPONSE_BUFSIZE];
        respBuf[HDR] = (byte) 0xFE;
        respBuf[HDR + 1] = 'S';
        respBuf[HDR + 2] = 'M';
        respBuf[HDR + 3] = 'B';

        return new SMBSrvPacket(respBuf);
    }

    /**
     * Build the negotiate response
     *
     * @param respPkt    SMBSrvPacket
     * @param selDialect int Selected dialect, a Dialect.SMB* value
     * @param negCtx     NegotiateContext
     * @return int Length of the response
     * @exception SMBSrvException Negotiation failed
     */
    final int packNegotiateResponse(SMBSrvPacket respPkt, int selDialect, NegotiateContext negCtx)
            throws SMBSrvException {

        int dialectRev = Dialect.SMB2IdToDialect(selDialect);
        if (dialectRev == -1)
            throw new SMBSrvException(SMBStatus.NTNotSupported);

        // A null SMB2 context indicates an SMB1 multi-protocol negotiate
        SMB2NegotiateContext smb2Ctx = negCtx instanceof SMB2NegotiateContext ? (SMB2NegotiateContext) negCtx : null;
        boolean wildcard = dialectRev == SMB2.DIALECT_WILDCARD;

        if (dialectRev == SMB2.DIALECT_311 && (smb2Ctx == null || !smb2Ctx.hasPreauthSHA512()))
            throw new SMBSrvException(SMBStatus.NTInvalidParameter);

        SMBServer server = m_sess.getSMBServer();
        SMBConfigSection config = server.getSMBConfiguration();

        m_signingRequired = config.isSMB2SigningRequired();
        m_encryptionRequired = config.isSMB3EncryptionRequired();

        if (smb2Ctx != null) {
            m_clientGuid = smb2Ctx.getClientGuid();
            m_clientSecMode = smb2Ctx.getSecurityMode();
            m_clientCaps = smb2Ctx.getCapabilities();
        }

        // Select the capabilities and encryption cipher
        int caps = 0;
        int cipherId = SMB2.CIPHER_NONE;

        // Multi-credit requests, which allow reads and writes larger than 64K. The length field of the NetBIOS
        // session transport is too small for such requests, so only offer them on a direct TCP connection.
        if (!wildcard && dialectRev >= SMB2.DIALECT_210 && m_sess.isProtocol() == Protocol.TCPIP)
            caps |= SMB2.CAP_LARGE_MTU;

        if (!wildcard && config.hasSMB3Encryption() && smb2Ctx != null) {
            if (dialectRev >= SMB2.DIALECT_311) {
                if (smb2Ctx.hasCipher(SMB2.CIPHER_AES128_GCM))
                    cipherId = SMB2.CIPHER_AES128_GCM;
                else if (smb2Ctx.hasCipher(SMB2.CIPHER_AES128_CCM))
                    cipherId = SMB2.CIPHER_AES128_CCM;
            }
            else if (dialectRev >= SMB2.DIALECT_300 && (m_clientCaps & SMB2.CAP_ENCRYPTION) != 0) {
                cipherId = SMB2.CIPHER_AES128_CCM;
                caps |= SMB2.CAP_ENCRYPTION;
            }
        }

        int maxIoSize = MIN_IO_SIZE;
        if ((caps & SMB2.CAP_LARGE_MTU) != 0)
            maxIoSize = largestIoSize();

        int secMode = SMB2.NEG_SIGNING_ENABLED;
        if (m_signingRequired)
            secMode |= SMB2.NEG_SIGNING_REQUIRED;

        m_dialectRev = wildcard ? 0 : dialectRev;
        m_serverCaps = caps;
        m_serverSecMode = secMode;
        m_cipherId = cipherId;
        m_maxIoSize = maxIoSize;

        int credits;
        synchronized (m_creditLock) {
            m_credits = 0;
            credits = Math.max(1, Math.min(m_negCreditRequest, MAX_CREDITS));
            m_credits = credits;
        }

        // Build the response
        byte[] secBlob = SMB2Authenticator.getNegotiateToken();

        SMB2Buf out = new SMB2Buf(NEG_RESPONSE_BUFSIZE);
        out.position(HDR);

        // Header
        out.putByte(0xFE);
        out.putByte('S');
        out.putByte('M');
        out.putByte('B');
        out.putShort(SMB2.HEADER_LEN);
        out.putShort(0);                            // credit charge
        out.putInt(SMB2.STATUS_SUCCESS);
        out.putShort(SMB2.CMD_NEGOTIATE);
        out.putShort(credits);
        out.putInt(SMB2.FLG_SERVER_TO_REDIR);
        out.putInt(0);                              // next command
        out.putLong(m_negMessageId);
        out.putInt(0);                              // process id
        out.putInt(0);                              // tree id
        out.putLong(0);                             // session id
        out.putZeros(SMB2.SIGNATURE_LEN);

        // Body
        int ctxCountPos;
        int ctxOffsetPos;

        out.putShort(65);
        out.putShort(secMode);
        out.putShort(dialectRev);
        ctxCountPos = out.position();
        out.putShort(0);                            // negotiate context count
        out.putBytes(server.getServerGUID().getBytes(), 0, 16);
        out.putInt(caps);
        out.putInt(maxIoSize);                      // max transact size
        out.putInt(maxIoSize);                      // max read size
        out.putInt(maxIoSize);                      // max write size
        out.putLong(toNTTime(System.currentTimeMillis()));
        out.putLong(s_serverStartTime);
        out.putShort(SMB2.HEADER_LEN + NEG_RESPONSE_FIXED);
        out.putShort(secBlob.length);
        ctxOffsetPos = out.position();
        out.putInt(0);                              // negotiate context offset
        out.putBytes(secBlob);

        if (dialectRev == SMB2.DIALECT_311) {
            int ctxCount = 0;

            out.align(HDR, 8);
            out.setIntAt(ctxOffsetPos, out.position() - HDR);

            // Pre-authentication integrity capabilities
            out.putShort(SMB2.CTX_PREAUTH_INTEGRITY);
            out.putShort(6 + PREAUTH_SALT_LEN);
            out.putInt(0);
            out.putShort(1);                        // hash algorithm count
            out.putShort(PREAUTH_SALT_LEN);
            out.putShort(SMB2.HASH_SHA512);
            out.putBytes(SMB2Crypto.randomBytes(PREAUTH_SALT_LEN));
            ctxCount++;

            // Encryption capabilities, the selected cipher or zero if there is no cipher in common
            if (smb2Ctx.getCiphers().length > 0) {
                out.align(HDR, 8);
                out.putShort(SMB2.CTX_ENCRYPTION);
                out.putShort(4);
                out.putInt(0);
                out.putShort(1);
                out.putShort(cipherId);
                ctxCount++;
            }

            // Signing capabilities, only AES-CMAC is supported which is also the default
            if (smb2Ctx.hasSigningAlgorithm(SMB2.SIGN_AES_CMAC)) {
                out.align(HDR, 8);
                out.putShort(SMB2.CTX_SIGNING);
                out.putShort(4);
                out.putInt(0);
                out.putShort(1);
                out.putShort(SMB2.SIGN_AES_CMAC);
                ctxCount++;
            }

            out.setShortAt(ctxCountPos, ctxCount);
        }

        int respLen = out.position() - HDR;
        byte[] respBuf = respPkt.getBuffer();

        if (respLen + HDR > respBuf.length)
            throw new SMBSrvException(SMBStatus.NTBufferOverflow);
        System.arraycopy(out.array(), HDR, respBuf, HDR, respLen);

        // Complete the connection pre-authentication integrity hash
        if (dialectRev == SMB2.DIALECT_311) {
            try {
                m_preauthHash = SMB2Crypto.updatePreauthHash(m_negRequestHash, respBuf, HDR, respLen);
            }
            catch (GeneralSecurityException ex) {
                throw new SMBSrvException(SMBStatus.NTInvalidParameter, ex);
            }
        }
        m_negRequestHash = null;

        if (hasDebug(SMBSrvSession.Dbg.NEGOTIATE))
            debug("Negotiated dialect 0x" + Integer.toHexString(dialectRev) + ", caps=0x" + Integer.toHexString(caps)
                    + ", cipher=" + cipherId + ", maxIO=" + maxIoSize);

        return respLen;
    }

    /**
     * Work out the largest read/write size that can be supported using the configured packet pool
     *
     * @return int
     */
    private int largestIoSize() {
        SMBPacketPool pool = m_sess.getPacketPool();

        int largest = pool.getLargestSize();
        if (pool.allowsOverSizedAllocations())
            largest = Math.max(largest, pool.getMaximumOverSizedAllocation());

        int ioSize = ((largest - IO_HEADROOM) / MIN_IO_SIZE) * MIN_IO_SIZE;
        return Math.max(MIN_IO_SIZE, Math.min(ioSize, MAX_IO_SIZE));
    }

    //-------------------------------------------------------------------------------------------------------------
    // Request processing
    //-------------------------------------------------------------------------------------------------------------

    @Override
    public boolean runProtocol(SMBSrvPacket smbPkt)
            throws IOException, SMBSrvException, TooManyConnectionsException {

        byte[] buf = smbPkt.getBuffer();
        int off = HDR;
        int len = smbPkt.getReceivedLength() - HDR;

        // Decrypt the request if it has been sent using a transform header
        SMB2Session encSession = null;

        if (len >= 4 && buf[off] == (byte) 0xFD) {
            encSession = len >= SMB2.TRANSFORM_HEADER_LEN
                    ? m_sessions.get(SMB2Buf.getLong(buf, off + SMB2.TF_OFF_SESSION_ID)) : null;

            if (encSession == null || !encSession.valid || !encSession.canEncrypt() || m_cipherId == SMB2.CIPHER_NONE) {
                m_sess.hangupSession("Invalid encrypted SMB2 request");
                return true;
            }

            try {
                buf = SMB2Crypto.decryptMessage(m_cipherId, encSession.decryptKey, buf, off, len);
                off = 0;
                len = buf.length;
            }
            catch (GeneralSecurityException ex) {
                m_sess.hangupSession("SMB2 decryption failed");
                return true;
            }
        }

        SMB2Buf out = new SMB2Buf(512);
        out.position(HDR);

        List<ResponseInfo> responses = new ArrayList<ResponseInfo>(4);
        Chain chain = new Chain();

        int pos = off;
        int remaining = len;

        while (remaining > 0) {

            // Validate the header
            if (remaining < SMB2.HEADER_LEN || buf[pos] != (byte) 0xFE || buf[pos + 1] != 'S' || buf[pos + 2] != 'M'
                    || buf[pos + 3] != 'B' || SMB2Buf.getShort(buf, pos + SMB2.OFF_STRUCT_SIZE) != SMB2.HEADER_LEN) {
                m_sess.hangupSession("Invalid SMB2 header");
                break;
            }

            int next = SMB2Buf.getInt(buf, pos + SMB2.OFF_NEXT_COMMAND);
            if (next != 0 && (next < SMB2.HEADER_LEN || next > remaining || (next & 7) != 0)) {
                m_sess.hangupSession("Invalid SMB2 compound request");
                break;
            }

            int msgLen = next != 0 ? next : remaining;

            SMB2Request req = new SMB2Request(buf, pos, msgLen, encSession != null);
            req.lastInChain = next == 0;

            if (req.command() == SMB2.CMD_NEGOTIATE) {
                // The dialect cannot be re-negotiated on an established connection
                m_sess.hangupSession("Unexpected SMB2 negotiate");
                break;
            }

            processRequest(req, encSession, chain, out, responses);

            if (next == 0)
                break;
            pos += next;
            remaining -= next;
        }

        if (!responses.isEmpty())
            sendResponses(out, responses, encSession);

        return true;
    }

    /**
     * Process a single request, appending the response to the output buffer
     *
     * @param req        SMB2Request
     * @param encSession Session the packet was decrypted with, or null
     * @param chain      Chain
     * @param out        SMB2Buf
     * @param responses  List of responses built so far
     */
    private void processRequest(SMB2Request req, SMB2Session encSession, Chain chain, SMB2Buf out, List<ResponseInfo> responses) {

        int cmd = req.command();
        int status;
        byte[] errorData = null;

        // Responses within a compound are aligned on 8 byte boundaries
        out.align(HDR, 8);
        int hdrPos = out.position();
        out.putZeros(SMB2.HEADER_LEN);
        int bodyPos = out.position();

        try {
            // Related requests use the session, tree and file from the previous request in the chain
            if (req.hasFlag(SMB2.FLG_RELATED_OPERATIONS)) {
                if (chain.first)
                    throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

                req.sessionId = chain.sessionId;
                req.treeId = chain.treeId;
                req.relatedFileId = chain.fileId;
                req.chainError = chain.createError;
            }

            status = validateAndDispatch(req, encSession, out);
        }
        catch (SMB2Exception ex) {
            status = ex.getStatus();
            errorData = ex.getErrorData();

            // Discard any partially built response
            out.position(bodyPos);
        }
        catch (Throwable ex) {
            status = mapException(ex);
            out.position(bodyPos);

            if (Debug.EnableError && m_sess.hasDebug(SMBSrvSession.Dbg.ERROR)) {
                debug("Error processing " + SMB2.commandName(cmd) + ": " + ex);
                if (!(ex instanceof IOException))
                    Debug.println(ex);
            }
        }

        // Update the compound chain state
        chain.first = false;
        chain.sessionId = req.sessionId;
        chain.treeId = req.treeId;
        if (req.usedFileId != SMB2Request.RELATED_ID)
            chain.fileId = req.usedFileId;
        if (cmd == SMB2.CMD_CREATE) {
            chain.createError = SMB2.isError(status) ? status : 0;
            if (SMB2.isError(status))
                chain.fileId = SMB2Request.RELATED_ID;
        }

        if (status == STS_NO_RESPONSE) {
            out.position(hdrPos);
            return;
        }

        // Use the standard error response body if the command did not build a response
        boolean failed = SMB2.isError(status) && status != SMB2.STATUS_MORE_PROCESSING_REQUIRED;

        if (failed || out.position() == bodyPos) {
            out.position(bodyPos);
            writeErrorBody(out, errorData);
        }

        if (failed && hasDebug(SMBSrvSession.Dbg.ERROR))
            debug(SMB2.commandName(cmd) + " failed, status=0x" + Integer.toHexString(status));

        // Fill in the header
        boolean async = status == SMB2.STATUS_PENDING && req.pendingAsyncId != 0;

        writeHeader(out.array(), hdrPos, cmd, status, req.creditCharge(), grantCredits(req),
                req.flags() & SMB2.FLG_RELATED_OPERATIONS, req.messageId(), async, req.pendingAsyncId, req.processId(),
                req.treeId, req.sessionId);

        // Work out if the response should be signed, encrypted responses are not signed
        SMB2Session session = req.session;
        SMB2Session signSession = null;

        if (session != null && session.hasSigningKey() && !req.isEncrypted()) {
            if (req.signed || req.signResponse || (session.signingRequired && session.valid))
                signSession = session;
        }

        SMB2Session preauthSession = status == SMB2.STATUS_MORE_PROCESSING_REQUIRED ? req.preauthSession : null;

        responses.add(new ResponseInfo(hdrPos, signSession, preauthSession));
    }

    /**
     * Validate the session, tree and signature of a request, then run the command handler
     *
     * @param req        SMB2Request
     * @param encSession SMB2Session
     * @param out        SMB2Buf
     * @return int NT status
     * @exception Exception Error processing the request
     */
    private int validateAndDispatch(SMB2Request req, SMB2Session encSession, SMB2Buf out)
            throws Exception {

        int cmd = req.command();

        if (cmd == SMB2.CMD_ECHO) {
            req.checkBody(4, 4);
            out.putShort(4);
            out.putShort(0);
            return SMB2.STATUS_SUCCESS;
        }

        if (cmd == SMB2.CMD_CANCEL)
            return handleCancel(req);

        if (cmd == SMB2.CMD_SESSION_SETUP)
            return handleSessionSetup(req, out);

        // All other commands require an authenticated session
        SMB2Session session = m_sessions.get(req.sessionId);
        if (session == null || !session.valid)
            throw new SMB2Exception(SMB2.STATUS_USER_SESSION_DELETED);

        req.session = session;

        if (req.isEncrypted()) {
            if (encSession != session)
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
        }
        else {
            if (session.encryptData)
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

            if (req.hasFlag(SMB2.FLG_SIGNED) && session.hasSigningKey()) {
                if (!SMB2Crypto.verifySignature(m_dialectRev, session.signingKey, req.buffer(), req.offset(), req.length())) {
                    if (hasDebug(SMBSrvSession.Dbg.SIGNING) || hasDebug(SMBSrvSession.Dbg.ERROR))
                        debug("Invalid signature on " + SMB2.commandName(cmd) + " request, " + session);
                    throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
                }
                req.signed = true;
            }
            else if (req.hasFlag(SMB2.FLG_SIGNED)) {

                // Guest and anonymous sessions do not have a key that is shared with the client, so a signature
                // cannot be verified. Some clients, such as smbj, sign their requests anyway using a key derived
                // from the credentials they tried to log on with. As the session is not authenticated there is
                // nothing to protect, so the signature is ignored rather than failing the request.
            }
            else if (session.signingRequired) {
                if (hasDebug(SMBSrvSession.Dbg.SIGNING) || hasDebug(SMBSrvSession.Dbg.ERROR))
                    debug("Unsigned " + SMB2.commandName(cmd) + " request on a session that requires signing, " + session);
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
            }
        }

        // Make the user of this request the current user of the connection
        if (m_sess.findVirtualCircuit(session.vc.getId()) == null)
            throw new SMB2Exception(SMB2.STATUS_USER_SESSION_DELETED);

        if (cmd == SMB2.CMD_LOGOFF)
            return handleLogoff(req, out);
        if (cmd == SMB2.CMD_TREE_CONNECT)
            return handleTreeConnect(req, out);

        // The remaining commands require a tree connection
        TreeConnection tree = session.vc.findConnection(req.treeId);
        if (tree == null)
            throw new SMB2Exception(SMB2.STATUS_NETWORK_NAME_DELETED);

        req.tree = tree;

        switch (cmd) {
            case SMB2.CMD_TREE_DISCONNECT:
                return handleTreeDisconnect(req, out);
            case SMB2.CMD_CREATE:
                return m_fileOps.create(req, out);
            case SMB2.CMD_CLOSE:
                return m_fileOps.close(req, out);
            case SMB2.CMD_FLUSH:
                return m_fileOps.flush(req, out);
            case SMB2.CMD_READ:
                return m_fileOps.read(req, out);
            case SMB2.CMD_WRITE:
                return m_fileOps.write(req, out);
            case SMB2.CMD_LOCK:
                return m_fileOps.lock(req, out);
            case SMB2.CMD_IOCTL:
                return m_ioctlOps.ioctl(req, out);
            case SMB2.CMD_QUERY_DIRECTORY:
                return m_infoOps.queryDirectory(req, out);
            case SMB2.CMD_CHANGE_NOTIFY:
                return handleChangeNotify(req, out);
            case SMB2.CMD_QUERY_INFO:
                return m_infoOps.queryInfo(req, out);
            case SMB2.CMD_SET_INFO:
                return m_infoOps.setInfo(req, out);
            case SMB2.CMD_OPLOCK_BREAK:
                // Oplocks and leases are never granted, so there is nothing to acknowledge
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
            default:
                throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);
        }
    }

    /**
     * Calculate the credits to grant in the response to a request
     *
     * @param req SMB2Request
     * @return int
     */
    private int grantCredits(SMB2Request req) {
        int charge = Math.max(1, req.creditCharge());
        int requested = Math.max(1, req.creditRequest());

        synchronized (m_creditLock) {
            m_credits = Math.max(0, m_credits - charge);

            int grant = Math.max(1, Math.min(requested, MAX_CREDITS - m_credits));
            m_credits += grant;
            return grant;
        }
    }

    /**
     * Write an SMB2 response header
     */
    private static void writeHeader(byte[] buf, int pos, int cmd, int status, int creditCharge, int credits, int flags,
                                    long messageId, boolean async, long asyncId, int processId, int treeId, long sessionId) {
        Arrays.fill(buf, pos, pos + SMB2.HEADER_LEN, (byte) 0);

        buf[pos] = (byte) 0xFE;
        buf[pos + 1] = 'S';
        buf[pos + 2] = 'M';
        buf[pos + 3] = 'B';

        putShort(buf, pos + SMB2.OFF_STRUCT_SIZE, SMB2.HEADER_LEN);
        putShort(buf, pos + SMB2.OFF_CREDIT_CHARGE, creditCharge);
        putInt(buf, pos + SMB2.OFF_STATUS, status);
        putShort(buf, pos + SMB2.OFF_COMMAND, cmd);
        putShort(buf, pos + SMB2.OFF_CREDITS, credits);
        putInt(buf, pos + SMB2.OFF_FLAGS, SMB2.FLG_SERVER_TO_REDIR | flags | (async ? SMB2.FLG_ASYNC_COMMAND : 0));
        putLong(buf, pos + SMB2.OFF_MESSAGE_ID, messageId);

        if (async)
            putLong(buf, pos + SMB2.OFF_ASYNC_ID, asyncId);
        else {
            putInt(buf, pos + SMB2.OFF_PROCESS_ID, processId);
            putInt(buf, pos + SMB2.OFF_TREE_ID, treeId);
        }

        putLong(buf, pos + SMB2.OFF_SESSION_ID, sessionId);
    }

    private static void putShort(byte[] buf, int pos, int val) {
        buf[pos] = (byte) val;
        buf[pos + 1] = (byte) (val >> 8);
    }

    private static void putInt(byte[] buf, int pos, int val) {
        putShort(buf, pos, val);
        putShort(buf, pos + 2, val >> 16);
    }

    private static void putLong(byte[] buf, int pos, long val) {
        putInt(buf, pos, (int) val);
        putInt(buf, pos + 4, (int) (val >>> 32));
    }

    /**
     * Write the standard error response body
     *
     * @param out       SMB2Buf
     * @param errorData byte[] Optional error data
     */
    private static void writeErrorBody(SMB2Buf out, byte[] errorData) {
        out.putShort(9);
        out.putShort(0);

        if (errorData != null && errorData.length > 0) {
            out.putInt(errorData.length);
            out.putBytes(errorData);
        }
        else {
            out.putInt(0);
            out.putByte(0);
        }
    }

    /**
     * Finalize and send the responses to a packet. The responses of a compound are chained together and signed
     * individually, then sent as a single packet.
     *
     * @param out        SMB2Buf
     * @param responses  List of responses
     * @param encSession Session to encrypt the responses with, or null
     * @exception IOException Socket error
     */
    private void sendResponses(SMB2Buf out, List<ResponseInfo> responses, SMB2Session encSession)
            throws IOException {

        // Pad the final response of a compound, clients expect each response to be 8 byte aligned
        if (responses.size() > 1)
            out.align(HDR, 8);

        byte[] buf = out.array();
        int end = out.position();

        try {
            for (int i = 0; i < responses.size(); i++) {
                ResponseInfo resp = responses.get(i);
                int respEnd = end;

                if (i + 1 < responses.size()) {
                    respEnd = responses.get(i + 1).hdrPos;
                    putInt(buf, resp.hdrPos + SMB2.OFF_NEXT_COMMAND, respEnd - resp.hdrPos);
                }

                int respLen = respEnd - resp.hdrPos;

                if (resp.signSession != null) {
                    int flags = SMB2Buf.getInt(buf, resp.hdrPos + SMB2.OFF_FLAGS);
                    putInt(buf, resp.hdrPos + SMB2.OFF_FLAGS, flags | SMB2.FLG_SIGNED);
                    SMB2Crypto.signMessage(m_dialectRev, resp.signSession.signingKey, buf, resp.hdrPos, respLen);
                }

                // Session setup responses that continue the authentication are part of the integrity hash
                if (resp.preauthSession != null && m_dialectRev >= SMB2.DIALECT_311)
                    resp.preauthSession.preauthHash = SMB2Crypto.updatePreauthHash(resp.preauthSession.preauthHash, buf,
                            resp.hdrPos, respLen);
            }

            sendPacket(buf, end - HDR, encSession);
        }
        catch (GeneralSecurityException ex) {
            m_sess.hangupSession("SMB2 response signing/encryption failed");
        }
    }

    /**
     * Send a packet to the client, encrypting it if required
     *
     * @param buf        byte[] Buffer with the message(s) starting at offset HDR
     * @param len        int Length of the message(s)
     * @param encSession SMB2Session
     * @exception IOException              Socket error
     * @exception GeneralSecurityException Encryption error
     */
    private void sendPacket(byte[] buf, int len, SMB2Session encSession)
            throws IOException, GeneralSecurityException {

        if (encSession != null) {
            byte[] encBuf = new byte[HDR + SMB2.TRANSFORM_HEADER_LEN + len + SMB2.SIGNATURE_LEN];
            int encLen = SMB2Crypto.encryptMessage(m_cipherId, encSession.encryptKey, encSession.getId(), buf, HDR, len,
                    encBuf, HDR);
            m_sess.sendResponseSMB(new SMBSrvPacket(encBuf), encLen);
        }
        else
            m_sess.sendResponseSMB(new SMBSrvPacket(buf), len);
    }

    //-------------------------------------------------------------------------------------------------------------
    // Session setup and logoff
    //-------------------------------------------------------------------------------------------------------------

    private int handleSessionSetup(SMB2Request req, SMB2Buf out)
            throws SMB2Exception, GeneralSecurityException {

        req.checkBody(25, 24);

        int flags = req.getByte(2);
        int secMode = req.getByte(3);
        int tokOff = req.getShort(12);
        int tokLen = req.getShort(14);

        // Multi-channel session binding is not supported
        if ((flags & SMB2.SESSION_FLAG_BINDING) != 0)
            throw new SMB2Exception(SMB2.STATUS_REQUEST_NOT_ACCEPTED);

        int tokPos = req.checkRange(tokOff, tokLen);
        byte[] token = Arrays.copyOfRange(req.buffer(), tokPos, tokPos + tokLen);

        // Find or create the session
        SMB2Session session;

        if (req.sessionId == 0) {
            if (m_sessions.size() >= MAX_SESSIONS) {

                // Make room by discarding logons that were started but never completed
                for (SMB2Session pending : m_sessions.values()) {
                    if (!pending.valid)
                        m_sessions.remove(pending.getId());
                }

                if (m_sessions.size() >= MAX_SESSIONS)
                    throw new SMB2Exception(SMB2.STATUS_INSUFFICIENT_RESOURCES);
            }

            session = new SMB2Session(s_sessionIds.incrementAndGet());
            session.preauthHash = m_preauthHash;
            session.authContext = new SMB2Authenticator.Context();

            m_sessions.put(session.getId(), session);
            req.sessionId = session.getId();
        }
        else {
            session = m_sessions.get(req.sessionId);
            if (session == null)
                throw new SMB2Exception(SMB2.STATUS_USER_SESSION_DELETED);

            // Re-authentication of an established session
            if (session.authContext == null)
                session.authContext = new SMB2Authenticator.Context();
        }

        req.session = session;

        boolean reauth = session.valid;

        if (reauth && req.hasFlag(SMB2.FLG_SIGNED) && session.hasSigningKey() && !req.isEncrypted()) {
            if (!SMB2Crypto.verifySignature(m_dialectRev, session.signingKey, req.buffer(), req.offset(), req.length()))
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
            req.signed = true;
        }

        if (m_dialectRev >= SMB2.DIALECT_311 && !reauth)
            session.preauthHash = SMB2Crypto.updatePreauthHash(session.preauthHash, req.buffer(), req.offset(), req.length());

        // Process the security token
        ISMBAuthenticator auth = m_sess.getSMBServer().getSMBAuthenticator();
        SMB2Authenticator.Context authCtx = session.authContext;

        SMB2Authenticator.Outcome outcome = SMB2Authenticator.process(authCtx, token, m_sess.getServerName(),
                SMB2Authenticator.accountSource(auth));

        boolean guest = false;
        boolean anonymous = false;

        switch (outcome.result) {
            case CHALLENGE:
                writeSessionSetupBody(out, 0, outcome.responseToken);
                req.preauthSession = session;
                return SMB2.STATUS_MORE_PROCESSING_REQUIRED;

            case AUTHENTICATED:
                break;

            case ANONYMOUS:
                anonymous = true;
                break;

            case UNKNOWN_USER:
                if (SMB2Authenticator.isGuestAllowed(auth)) {
                    guest = true;
                    break;
                }
                // Fall through

            default:
                failSessionSetup(session, authCtx);
                throw new SMB2Exception(SMB2.STATUS_LOGON_FAILURE);
        }

        // A session that cannot be encrypted is not acceptable if encryption is required
        if (m_encryptionRequired && (guest || anonymous || m_cipherId == SMB2.CIPHER_NONE)) {
            failSessionSetup(session, authCtx);
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
        }

        NTLMSSPServer ntlm = authCtx.getNTLM();
        session.authContext = null;

        if (!reauth) {
            session.guest = guest;
            session.anonymous = anonymous;

            // Create the client details and virtual circuit for the session
            String userName = ntlm.getUserName();
            if (guest && auth instanceof SMBAuthenticator)
                userName = ((SMBAuthenticator) auth).getGuestUserName();

            ClientInfo client = ClientInfo.createInfo(userName, null);
            client.setDomain(ntlm.getDomain());

            if (anonymous)
                client.setLogonType(ClientInfo.LogonType.Null);
            else if (guest)
                client.setGuest(true);
            else
                client.setLogonType(ClientInfo.LogonType.Normal);

            InetAddress remoteAddr = m_sess.hasRemoteAddress() ? m_sess.getRemoteAddress() : null;
            if (remoteAddr != null)
                client.setClientAddress(remoteAddr.getHostAddress());

            VirtualCircuit vc = m_sess.createVirtualCircuit(0, client);
            if (vc == null || m_sess.addVirtualCircuit(vc) == VirtualCircuit.InvalidID) {
                m_sessions.remove(session.getId());
                throw new SMB2Exception(SMB2.STATUS_INSUFFICIENT_RESOURCES);
            }

            vc.setLoggedOn(true);

            session.vc = vc;
            session.client = client;

            if (outcome.result == NTLMSSPServer.Result.AUTHENTICATED) {
                session.sessionKey = Arrays.copyOf(ntlm.getSessionKey(), 16);
                session.signingKey = SMB2Crypto.deriveSigningKey(m_dialectRev, session.sessionKey, session.preauthHash);

                if (m_cipherId != SMB2.CIPHER_NONE) {
                    session.decryptKey = SMB2Crypto.deriveDecryptionKey(m_dialectRev, session.sessionKey, session.preauthHash);
                    session.encryptKey = SMB2Crypto.deriveEncryptionKey(m_dialectRev, session.sessionKey, session.preauthHash);
                }

                session.signingRequired = m_signingRequired || (secMode & SMB2.NEG_SIGNING_REQUIRED) != 0
                        || (m_clientSecMode & SMB2.NEG_SIGNING_REQUIRED) != 0;
                session.encryptData = m_encryptionRequired && session.canEncrypt();
            }

            if (m_sess.getRemoteName() == null && !ntlm.getWorkstation().isEmpty())
                m_sess.setRemoteName(ntlm.getWorkstation());

            m_sess.setClientInformation(client);
            m_sess.setLoggedOn(true);

            session.valid = true;

            // Now that the client has logged on, accept requests of the size that was negotiated
            if (m_maxIoSize + IO_HEADROOM > m_sess.getPacketHandler().getMaximumPacketSize())
                m_sess.getPacketHandler().setMaximumPacketSize(m_maxIoSize + IO_HEADROOM);

            if (hasDebug(SMBSrvSession.Dbg.NEGOTIATE))
                debug("Session setup " + session + (session.signingRequired ? " signing" : "")
                        + (session.encryptData ? " encrypted" : ""));
        }

        int sessFlags = 0;
        if (session.guest)
            sessFlags |= SMB2.SESSION_IS_GUEST;
        else if (session.anonymous)
            sessFlags |= SMB2.SESSION_IS_NULL;
        if (session.encryptData)
            sessFlags |= SMB2.SESSION_ENCRYPT_DATA;

        writeSessionSetupBody(out, sessFlags, outcome.responseToken);

        // The final response of an authenticated session setup is always signed
        req.signResponse = session.hasSigningKey();

        return SMB2.STATUS_SUCCESS;
    }

    private static void writeSessionSetupBody(SMB2Buf out, int sessFlags, byte[] token) {
        out.putShort(9);
        out.putShort(sessFlags);
        out.putShort(SMB2.HEADER_LEN + 8);
        out.putShort(token != null ? token.length : 0);
        if (token != null && token.length > 0)
            out.putBytes(token);
        else
            out.putByte(0);
    }

    /**
     * Clean up after a failed authentication. A session that fails to re-authenticate is closed.
     *
     * @param session SMB2Session
     * @param authCtx Context
     */
    private void failSessionSetup(SMB2Session session, SMB2Authenticator.Context authCtx) {
        session.authContext = null;
        m_sessions.remove(session.getId());

        if (session.valid)
            closeSession(session);

        if (hasDebug(SMBSrvSession.Dbg.NEGOTIATE) || hasDebug(SMBSrvSession.Dbg.ERROR))
            debug("Logon failed for user '" + authCtx.getNTLM().getUserName() + "'"
                    + (authCtx.getFailureReason() != null ? ", " + authCtx.getFailureReason() : ""));
    }

    private int handleLogoff(SMB2Request req, SMB2Buf out)
            throws SMB2Exception {

        req.checkBody(4, 4);

        SMB2Session session = req.session;

        m_sessions.remove(session.getId());
        closeSession(session);

        out.putShort(4);
        out.putShort(0);
        return SMB2.STATUS_SUCCESS;
    }

    /**
     * Close a session, releasing all of its tree connections and open files
     *
     * @param session SMB2Session
     */
    private void closeSession(SMB2Session session) {
        session.valid = false;

        releaseOpens(session, -1);

        if (session.vc != null)
            m_sess.removeVirtualCircuit(session.vc.getId());
    }

    /**
     * Release the protocol level state of the open files of a session. The files themselves are closed by the
     * tree connection.
     *
     * @param session SMB2Session
     * @param treeId  int Tree to release the files of, or -1 for all trees
     */
    private void releaseOpens(SMB2Session session, int treeId) {
        for (SMB2Open open : session.opens.values()) {
            if (treeId == -1 || open.getTreeId() == treeId) {
                session.opens.remove(open.getFileId());
                releaseOpen(open, false);
            }
        }
    }

    //-------------------------------------------------------------------------------------------------------------
    // Tree connect and disconnect
    //-------------------------------------------------------------------------------------------------------------

    private int handleTreeConnect(SMB2Request req, SMB2Buf out)
            throws SMB2Exception {

        req.checkBody(9, 8);

        int pathOff = req.getShort(4);
        int pathLen = req.getShort(6);
        int pathPos = req.checkRange(pathOff, pathLen);

        String uncPath = SMB2Buf.getUnicode(req.buffer(), pathPos, pathLen & ~1);

        // Split the \\server\share path
        String hostName = null;
        String shareName = uncPath;

        int idx = uncPath.lastIndexOf('\\');
        if (idx != -1) {
            shareName = uncPath.substring(idx + 1);

            String host = uncPath.substring(0, idx);
            while (host.startsWith("\\"))
                host = host.substring(1);
            if (!host.isEmpty())
                hostName = host;
        }

        if (shareName.isEmpty())
            throw new SMB2Exception(SMB2.STATUS_BAD_NETWORK_NAME);

        SMB2Session session = req.session;
        SMBServer server = m_sess.getSMBServer();
        ISMBAuthenticator auth = server.getSMBAuthenticator();

        ShareType shareType = shareName.equalsIgnoreCase("IPC$") ? ShareType.ADMINPIPE : ShareType.UNKNOWN;

        // Anonymous sessions may only use the IPC$ share, unless the server is open to guests
        if (session.anonymous && shareType != ShareType.ADMINPIPE && !SMB2Authenticator.isGuestAllowed(auth))
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

        SharedDevice share = null;
        try {
            share = server.findShare(hostName, shareName, shareType, m_sess, true);
        }
        catch (Exception ex) {
            if (hasDebug(SMBSrvSession.Dbg.TREE))
                debug("Tree connect failed for " + uncPath + ": " + ex);
        }

        if (share == null)
            throw new SMB2Exception(SMB2.STATUS_BAD_NETWORK_NAME);

        // Check the access to the share
        ISMBAuthenticator.ShareStatus sharePerm = ISMBAuthenticator.ShareStatus.WRITEABLE;

        if (auth != null) {
            sharePerm = auth.authenticateShareConnect(session.client, share, null, m_sess);
            if (sharePerm == ISMBAuthenticator.ShareStatus.NO_ACCESS)
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
        }

        if (server.hasAccessControlManager() && share.hasAccessControls()) {
            AccessControlManager aclMgr = server.getAccessControlManager();
            int aclPerm = aclMgr.checkAccessControl(m_sess, share);

            if (aclPerm == FileAccess.NoAccess)
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
            if (aclPerm != AccessControl.Default)
                sharePerm = asShareStatus(aclPerm);
        }

        // Allocate the tree connection
        int treeId;
        try {
            treeId = session.vc.addConnection(share);
        }
        catch (TooManyConnectionsException ex) {
            throw new SMB2Exception(SMB2.STATUS_INSUFFICIENT_RESOURCES);
        }

        TreeConnection tree = session.vc.findConnection(treeId);
        tree.setPermission(sharePerm);

        req.treeId = treeId;
        req.tree = tree;

        if (tree.getInterface() != null)
            tree.getInterface().treeOpened(m_sess, tree);

        if (hasDebug(SMBSrvSession.Dbg.TREE))
            debug("Tree connect " + uncPath + " tid=" + treeId + " perm=" + sharePerm);

        // Build the response
        int smbShareType = SMB2.SHARE_TYPE_DISK;
        int maxAccess = sharePerm == ISMBAuthenticator.ShareStatus.WRITEABLE ? SMB2.ACC_FILE_ALL : SMB2.ACC_FILE_READ_ONLY;

        if (share.getType() == ShareType.ADMINPIPE || share.getType() == ShareType.NAMEDPIPE) {
            smbShareType = SMB2.SHARE_TYPE_PIPE;
            maxAccess = SMB2.ACC_FILE_ALL;
        }
        else if (share.getType() == ShareType.PRINTER)
            smbShareType = SMB2.SHARE_TYPE_PRINT;

        out.putShort(16);
        out.putByte(smbShareType);
        out.putByte(0);
        out.putInt(0);                  // share flags
        out.putInt(0);                  // share capabilities
        out.putInt(maxAccess);

        return SMB2.STATUS_SUCCESS;
    }

    private int handleTreeDisconnect(SMB2Request req, SMB2Buf out)
            throws SMB2Exception {

        req.checkBody(4, 4);

        SMB2Session session = req.session;
        TreeConnection tree = req.tree;

        releaseOpens(session, req.treeId);

        session.vc.removeConnection(req.treeId, m_sess);

        if (tree.getInterface() != null)
            tree.getInterface().treeClosed(m_sess, tree);

        if (hasDebug(SMBSrvSession.Dbg.TREE))
            debug("Tree disconnect tid=" + req.treeId);

        out.putShort(4);
        out.putShort(0);
        return SMB2.STATUS_SUCCESS;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Open file tracking
    //-------------------------------------------------------------------------------------------------------------

    /**
     * Find the open file for a request
     *
     * @param req SMB2Request
     * @param pos int Position of the file id in the request body
     * @return SMB2Open
     * @exception SMB2Exception File is not open
     */
    final SMB2Open findOpen(SMB2Request req, int pos)
            throws SMB2Exception {

        long fileId = req.fileId(pos);

        // A related request that follows a failed create fails with the same status
        if (fileId == SMB2Request.RELATED_ID)
            throw new SMB2Exception(req.chainError != 0 ? req.chainError : SMB2.STATUS_FILE_CLOSED);

        SMB2Open open = req.session.opens.get(fileId);
        if (open == null || open.closed || open.getTreeId() != req.treeId)
            throw new SMB2Exception(SMB2.STATUS_FILE_CLOSED);

        req.usedFileId = fileId;
        return open;
    }

    /**
     * Register a newly opened file
     *
     * @param req       SMB2Request
     * @param file      NetworkFile
     * @param handle    int File handle allocated by the tree connection
     * @param path      String
     * @param access    int Granted access mask
     * @param directory boolean
     * @param pipe      boolean
     * @return SMB2Open
     */
    final SMB2Open addOpen(SMB2Request req, NetworkFile file, int handle, String path, int access, boolean directory,
                           boolean pipe) {
        long fileId = m_fileIds.incrementAndGet();

        SMB2Open open = new SMB2Open(fileId, req.session, req.treeId, req.tree, file, handle, path, access, directory, pipe);
        req.session.opens.put(fileId, open);
        req.usedFileId = fileId;
        return open;
    }

    /**
     * Remove an open file that is being closed by the client
     *
     * @param open SMB2Open
     */
    final void removeOpen(SMB2Open open) {
        open.getSession().opens.remove(open.getFileId());
        releaseOpen(open, true);
    }

    /**
     * Release the protocol level resources held by an open file
     *
     * @param open   SMB2Open
     * @param notify boolean true to complete an outstanding change notification request
     */
    private void releaseOpen(SMB2Open open, boolean notify) {
        open.closed = true;
        open.closeSearch();

        if (open.hasLocks)
            SMB2LockManager.releaseLocks(open);

        PendingRequest pending = open.pendingNotify;
        if (pending != null) {
            if (notify && !m_sess.isShutdown())
                completeChangeNotify(pending, SMB2.STATUS_NOTIFY_CLEANUP);
            else
                discardPending(pending);
        }
    }

    //-------------------------------------------------------------------------------------------------------------
    // Change notification and asynchronous requests
    //-------------------------------------------------------------------------------------------------------------

    /**
     * Change notification requests are held as asynchronous requests until they are cancelled or the directory
     * handle is closed. Clients such as Windows Explorer expect the request to be accepted but cope with never
     * receiving a notification.
     */
    private int handleChangeNotify(SMB2Request req, SMB2Buf out)
            throws SMB2Exception {

        req.checkBody(32, 32);

        int outLen = req.getInt(4);
        SMB2Open open = findOpen(req, 8);

        if (!open.isDirectory())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
        if (outLen > m_maxIoSize)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
        if (m_pending.size() >= MAX_PENDING_REQUESTS || open.pendingNotify != null)
            throw new SMB2Exception(SMB2.STATUS_INSUFFICIENT_RESOURCES);

        PendingRequest pending = new PendingRequest(m_asyncIds.incrementAndGet(), req, open, outLen);

        m_pending.put(pending.asyncId, pending);
        open.pendingNotify = pending;

        // The file may have been closed whilst the request was being queued
        if (open.closed) {
            discardPending(pending);
            throw new SMB2Exception(SMB2.STATUS_FILE_CLOSED);
        }

        req.pendingAsyncId = pending.asyncId;
        return SMB2.STATUS_PENDING;
    }

    private int handleCancel(SMB2Request req) {

        PendingRequest pending = null;

        if (req.hasFlag(SMB2.FLG_ASYNC_COMMAND))
            pending = m_pending.get(req.asyncId());
        else {
            long messageId = req.messageId();
            for (PendingRequest cur : m_pending.values()) {
                if (cur.messageId == messageId) {
                    pending = cur;
                    break;
                }
            }
        }

        if (pending != null)
            completeAsync(pending, SMB2.STATUS_CANCELLED, null);

        // There is no response to a cancel request
        return STS_NO_RESPONSE;
    }

    private void completeChangeNotify(PendingRequest pending, int status) {

        // Change notify response with an empty output buffer
        SMB2Buf body = new SMB2Buf(16);
        body.putShort(9);
        body.putShort(SMB2.HEADER_LEN + 8);
        body.putInt(0);
        body.putByte(0);

        completeAsync(pending, status, Arrays.copyOf(body.array(), body.position()));
    }

    private boolean discardPending(PendingRequest pending) {
        if (!pending.m_completed.compareAndSet(false, true))
            return false;

        m_pending.remove(pending.asyncId);
        if (pending.open != null && pending.open.pendingNotify == pending)
            pending.open.pendingNotify = null;
        return true;
    }

    /**
     * Send the final response for an asynchronous request
     *
     * @param pending PendingRequest
     * @param status  int
     * @param body    byte[] Response body, or null to send an error response
     */
    private void completeAsync(PendingRequest pending, int status, byte[] body) {

        if (!discardPending(pending))
            return;

        SMB2Buf out = new SMB2Buf(HDR + SMB2.HEADER_LEN + (body != null ? body.length : 9));
        out.position(HDR);
        out.putZeros(SMB2.HEADER_LEN);

        if (body != null)
            out.putBytes(body);
        else
            writeErrorBody(out, null);

        // Credits were granted by the interim response
        byte[] buf = out.array();
        SMB2Session session = pending.session;

        writeHeader(buf, HDR, pending.command, status, 0, 0, 0, pending.messageId, true, pending.asyncId, 0, 0,
                session.getId());

        int len = out.position() - HDR;

        try {
            if (pending.encrypted && session.canEncrypt())
                sendPacket(buf, len, session);
            else {
                if (session.hasSigningKey() && (pending.signed || session.signingRequired)) {
                    putInt(buf, HDR + SMB2.OFF_FLAGS, SMB2Buf.getInt(buf, HDR + SMB2.OFF_FLAGS) | SMB2.FLG_SIGNED);
                    SMB2Crypto.signMessage(m_dialectRev, session.signingKey, buf, HDR, len);
                }
                sendPacket(buf, len, null);
            }
        }
        catch (Exception ex) {
            if (hasDebug(SMBSrvSession.Dbg.ERROR))
                debug("Failed to send async response: " + ex);
        }
    }

    //-------------------------------------------------------------------------------------------------------------
    // Connection cleanup
    //-------------------------------------------------------------------------------------------------------------

    @Override
    public void virtualCircuitClosed(VirtualCircuit vc, SMBSrvSession sess) {

        // Release the protocol level state for the session that used the virtual circuit
        for (SMB2Session session : m_sessions.values()) {
            if (session.vc == vc) {
                m_sessions.remove(session.getId());
                session.valid = false;
                releaseOpens(session, -1);
            }
        }
    }

    @Override
    public void socketClosed(SMBSrvSession sess) {
        m_pending.clear();
    }

    @Override
    public void hangupSession(SMBSrvSession sess, String reason) {
        if (hasDebug(SMBSrvSession.Dbg.STATE))
            debug("Hangup session: " + reason);
    }

    //-------------------------------------------------------------------------------------------------------------
    // Error mapping
    //-------------------------------------------------------------------------------------------------------------

    /**
     * Map an exception thrown by a filesystem driver to an NT status code
     *
     * @param ex Throwable
     * @return int
     */
    static int mapException(Throwable ex) {
        if (ex instanceof SMB2Exception)
            return ((SMB2Exception) ex).getStatus();
        if (ex instanceof SMBSrvException) {
            SMBSrvException smbEx = (SMBSrvException) ex;
            return smbEx.hasNTErrorCode() && smbEx.getNTErrorCode() != 0 ? smbEx.getNTErrorCode() : SMB2.STATUS_UNSUCCESSFUL;
        }
        if (ex instanceof PathNotFoundException)
            return SMB2.STATUS_OBJECT_PATH_NOT_FOUND;
        if (ex instanceof FileNotFoundException || ex instanceof NoSuchFileException)
            return SMB2.STATUS_OBJECT_NAME_NOT_FOUND;
        if (ex instanceof AccessDeniedException || ex instanceof PermissionDeniedException
                || ex instanceof java.nio.file.AccessDeniedException || ex instanceof SecurityException)
            return SMB2.STATUS_ACCESS_DENIED;
        if (ex instanceof FileExistsException || ex instanceof FileAlreadyExistsException)
            return SMB2.STATUS_OBJECT_NAME_COLLISION;
        if (ex instanceof FileSharingException)
            return SMB2.STATUS_SHARING_VIOLATION;
        if (ex instanceof DirectoryNotEmptyException || ex instanceof java.nio.file.DirectoryNotEmptyException)
            return SMB2.STATUS_DIRECTORY_NOT_EMPTY;
        if (ex instanceof NotDirectoryException)
            return SMB2.STATUS_NOT_A_DIRECTORY;
        if (ex instanceof DiskFullException)
            return SMB2.STATUS_DISK_FULL;
        if (ex instanceof TooManyFilesException)
            return SMB2.STATUS_TOO_MANY_OPENED_FILES;
        if (ex instanceof FileNameException)
            return SMB2.STATUS_OBJECT_NAME_INVALID;
        if (ex instanceof IOException) {
            String msg = ex.getMessage();
            if (msg != null && (msg.contains("ENOSPC") || msg.contains("No space left")))
                return SMB2.STATUS_DISK_FULL;
            return SMB2.STATUS_UNSUCCESSFUL;
        }
        if (ex instanceof IndexOutOfBoundsException || ex instanceof IllegalArgumentException)
            return SMB2.STATUS_INVALID_PARAMETER;
        return SMB2.STATUS_INTERNAL_ERROR;
    }
}
