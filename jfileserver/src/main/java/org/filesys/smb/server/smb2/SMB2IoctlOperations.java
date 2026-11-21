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

import java.util.Arrays;

import org.filesys.server.filesys.FileInfo;
import org.filesys.server.filesys.NetworkFile;
import org.filesys.server.filesys.TooManyFilesException;
import org.filesys.server.filesys.TreeConnection;
import org.filesys.smb.Dialect;
import org.filesys.smb.DialectSelector;
import org.filesys.smb.dcerpc.DCEBuffer;
import org.filesys.smb.dcerpc.DCEBufferException;
import org.filesys.smb.dcerpc.DCEPipeType;
import org.filesys.smb.dcerpc.server.DCEPipeFile;
import org.filesys.smb.server.DCERPCHandler;
import org.filesys.smb.server.SMBSrvException;
import org.filesys.smb.server.SMBSrvSession;

/**
 * SMB2 IOCTL command, and the named pipe support used for DCE/RPC requests on the IPC$ share.
 */
final class SMB2IoctlOperations {

    private static final int IOCTL_RESPONSE_FIXED = 48;

    private static final int DCE_HEADER_LEN = 16;

    private static final String PIPE_PREFIX = "\\PIPE\\";

    // Access granted on a named pipe
    private static final int PIPE_ACCESS = 0x0012019F;

    private static final int STATUS_PIPE_EMPTY = 0xC00000D9;
    private static final int STATUS_NOT_A_REPARSE_POINT = 0xC0000275;

    private static final int VALIDATE_NEG_FIXED = 24;

    private final SMB2ProtocolHandler m_handler;

    SMB2IoctlOperations(SMB2ProtocolHandler handler) {
        m_handler = handler;
    }

    //-------------------------------------------------------------------------------------------------------------
    // IOCTL
    //-------------------------------------------------------------------------------------------------------------

    int ioctl(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(57, 56);

        int ctlCode = req.getInt(4);
        int inOff = req.getInt(24);
        int inLen = req.getInt(28);
        int maxOut = req.getInt(44);
        int flags = req.getInt(48);

        if ((flags & SMB2.IOCTL_FLAG_IS_FSCTL) == 0)
            throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);
        if (inLen < 0 || inLen > m_handler.maxIoSize() || maxOut < 0 || maxOut > m_handler.maxIoSize())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        byte[] buf = req.buffer();
        int inPos = inLen > 0 ? req.checkRange(inOff, inLen) : 0;

        byte[] output = new byte[0];
        int status = SMB2.STATUS_SUCCESS;

        switch (ctlCode) {
            case SMB2.FSCTL_VALIDATE_NEGOTIATE_INFO:
                output = validateNegotiateInfo(buf, inPos, inLen);
                break;

            case SMB2.FSCTL_PIPE_TRANSCEIVE: {
                SMB2Open open = m_handler.findOpen(req, 8);
                if (!open.isPipe())
                    throw new SMB2Exception(SMB2.STATUS_INVALID_DEVICE_REQUEST);

                boolean[] moreData = new boolean[1];
                pipeWrite(open, buf, inPos, inLen);
                output = pipeRead(open, maxOut, moreData);

                if (moreData[0])
                    status = SMB2.STATUS_BUFFER_OVERFLOW;
                break;
            }

            case SMB2.FSCTL_PIPE_WAIT:
                // Pipes are always available
                break;

            case SMB2.FSCTL_DFS_GET_REFERRALS:
            case SMB2.FSCTL_DFS_GET_REFERRALS_EX:
                // Not a DFS server
                throw new SMB2Exception(SMB2.STATUS_NOT_FOUND);

            case SMB2.FSCTL_GET_REPARSE_POINT:
                m_handler.findOpen(req, 8);
                throw new SMB2Exception(STATUS_NOT_A_REPARSE_POINT);

            case SMB2.FSCTL_QUERY_NETWORK_INTERFACE_INFO:
            case SMB2.FSCTL_SRV_ENUMERATE_SNAPSHOTS:
            case SMB2.FSCTL_SRV_REQUEST_RESUME_KEY:
            case SMB2.FSCTL_SRV_COPYCHUNK:
            case SMB2.FSCTL_SRV_COPYCHUNK_WRITE:
            case SMB2.FSCTL_PIPE_PEEK:
                throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);

            default:
                throw new SMB2Exception(SMB2.STATUS_INVALID_DEVICE_REQUEST);
        }

        // Build the response, echoing back the file id from the request
        out.putShort(49);
        out.putShort(0);
        out.putInt(ctlCode);
        out.putBytes(buf, req.body() + 8, 16);
        out.putInt(SMB2.HEADER_LEN + IOCTL_RESPONSE_FIXED);     // input offset
        out.putInt(0);                                          // input count
        out.putInt(SMB2.HEADER_LEN + IOCTL_RESPONSE_FIXED);     // output offset
        out.putInt(output.length);
        out.putInt(0);                                          // flags
        out.putInt(0);

        if (output.length > 0)
            out.putBytes(output);
        else
            out.putByte(0);

        return status;
    }

    /**
     * Process a validate negotiate information request. The client sends the values it used to negotiate the
     * connection in a signed request, so that tampering with the unsigned negotiate exchange can be detected.
     *
     * @param buf   byte[]
     * @param inPos int
     * @param inLen int
     * @return byte[] Response data
     * @exception SMB2Exception Invalid request
     */
    private byte[] validateNegotiateInfo(byte[] buf, int inPos, int inLen)
            throws SMB2Exception {

        if (inLen < VALIDATE_NEG_FIXED)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        int dialectCnt = SMB2Buf.getShort(buf, inPos + 22);
        if (dialectCnt == 0 || inLen < VALIDATE_NEG_FIXED + (dialectCnt * 2))
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        // Work out which dialect would be selected from the client's list
        SMBSrvSession sess = m_handler.sess();
        DialectSelector enabled = sess.getSMBServer().getSMBConfiguration().getEnabledDialects();
        int selected = 0;

        for (int i = 0; i < dialectCnt; i++) {
            int rev = SMB2Buf.getShort(buf, inPos + VALIDATE_NEG_FIXED + (i * 2));
            int dialectId = rev == SMB2.DIALECT_WILDCARD ? -1 : Dialect.SMB2DialectToId(rev);

            if (dialectId != -1 && enabled.hasDialect(dialectId) && rev > selected)
                selected = rev;
        }

        // A mismatch indicates that the negotiation was tampered with, the connection must be dropped
        if (selected != m_handler.dialectRevision()) {
            sess.hangupSession("SMB2 validate negotiate dialect mismatch");
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
        }

        SMB2Buf data = new SMB2Buf(24);
        data.putInt(m_handler.serverCapabilities());
        data.putBytes(sess.getSMBServer().getServerGUID().getBytes(), 0, 16);
        data.putShort(m_handler.serverSecurityMode());
        data.putShort(m_handler.dialectRevision());

        return Arrays.copyOf(data.array(), data.position());
    }

    //-------------------------------------------------------------------------------------------------------------
    // Named pipes
    //-------------------------------------------------------------------------------------------------------------

    /**
     * Open a named pipe on the IPC$ share
     *
     * @param req  SMB2Request
     * @param out  SMB2Buf
     * @param name String
     * @return int NT status
     * @exception SMB2Exception Pipe is not available
     */
    int createPipe(SMB2Request req, SMB2Buf out, String name)
            throws SMB2Exception {

        int hdrPos = out.position() - SMB2.HEADER_LEN;

        // The pipe name may or may not include the \PIPE\ prefix
        while (name.startsWith("\\"))
            name = name.substring(1);
        if (name.regionMatches(true, 0, PIPE_PREFIX, 1, PIPE_PREFIX.length() - 1))
            name = name.substring(PIPE_PREFIX.length() - 1);

        DCEPipeType pipeType = DCEPipeType.PIPE_INVALID;
        String fullName = PIPE_PREFIX + name;

        for (DCEPipeType curType : DCEPipeType.values()) {
            String typeName = curType == DCEPipeType.PIPE_INVALID ? null : DCEPipeType.getTypeAsString(curType);
            if (typeName != null && typeName.equalsIgnoreCase(fullName)) {
                pipeType = curType;
                break;
            }
        }

        if (pipeType == DCEPipeType.PIPE_INVALID)
            throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_NOT_FOUND);

        DCEPipeFile pipeFile = new DCEPipeFile(pipeType);
        if (!pipeFile.hasRequestHandler())
            throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_NOT_FOUND);

        pipeFile.setGrantedAccess(NetworkFile.Access.READ_WRITE);

        TreeConnection tree = req.tree;
        int handle;
        try {
            handle = tree.addFile(pipeFile, m_handler.sess());
        }
        catch (TooManyFilesException ex) {
            throw new SMB2Exception(SMB2.STATUS_TOO_MANY_OPENED_FILES);
        }

        SMB2Open open = m_handler.addOpen(req, pipeFile, handle, "\\" + name, PIPE_ACCESS, false, true);

        if (m_handler.hasDebug(SMBSrvSession.Dbg.IPC))
            m_handler.debug("Opened pipe " + open);

        FileInfo info = new FileInfo(name, 0L, SMB2.ATTR_NORMAL);
        info.setAllocationSize(4096);

        SMB2FileOperations.writeCreateResponse(out, hdrPos, SMB2.CREATE_ACTION_OPENED, info, open.getFileId(), new int[0],
                PIPE_ACCESS);

        return SMB2.STATUS_SUCCESS;
    }

    /**
     * Write a DCE/RPC request to a pipe. The request is processed immediately and the response buffered on the
     * pipe ready to be read.
     *
     * @param open SMB2Open
     * @param buf  byte[]
     * @param pos  int
     * @param len  int
     * @exception SMB2Exception Request failed
     */
    void pipeWrite(SMB2Open open, byte[] buf, int pos, int len)
            throws SMB2Exception {

        if (len < DCE_HEADER_LEN)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        DCEPipeFile pipeFile = (DCEPipeFile) open.getFile();

        // The DCE/RPC buffer uses absolute positions, give it a private copy of the request
        byte[] data = Arrays.copyOfRange(buf, pos, pos + len);

        synchronized (pipeFile) {
            try {
                DCERPCHandler.processDCEBuffer(m_handler.sess(), new DCEBuffer(data, 0, len), pipeFile, null);
            }
            catch (SMBSrvException ex) {
                throw new SMB2Exception(SMB2ProtocolHandler.mapException(ex));
            }
            catch (Exception ex) {
                if (m_handler.hasDebug(SMBSrvSession.Dbg.DCERPC))
                    m_handler.debug("DCE/RPC request failed: " + ex);
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
            }
        }
    }

    /**
     * Read buffered DCE/RPC response data from a pipe
     *
     * @param open     SMB2Open
     * @param maxLen   int
     * @param moreData boolean[] Set to true if there is more data available than was read
     * @return byte[]
     * @exception SMB2Exception No data is available
     */
    byte[] pipeRead(SMB2Open open, int maxLen, boolean[] moreData)
            throws SMB2Exception {

        DCEPipeFile pipeFile = (DCEPipeFile) open.getFile();

        synchronized (pipeFile) {
            DCEBuffer dceBuf = pipeFile.hasBufferedData() ? pipeFile.getBufferedData() : null;
            if (dceBuf == null || dceBuf.getAvailableLength() == 0)
                throw new SMB2Exception(STATUS_PIPE_EMPTY);

            // The response is sent as a single fragment, fill in the header on the first read
            if (dceBuf.getAvailableLength() == dceBuf.getLength()) {
                dceBuf.setHeaderValue(DCEBuffer.HDR_FLAGS, DCEBuffer.FLG_ONLYFRAG);
                dceBuf.setHeaderValue(DCEBuffer.HDR_FRAGLEN, dceBuf.getLength());
            }

            byte[] data = new byte[Math.min(dceBuf.getAvailableLength(), maxLen)];
            try {
                dceBuf.copyData(data, 0, data.length);
            }
            catch (DCEBufferException ex) {
                throw new SMB2Exception(SMB2.STATUS_INTERNAL_ERROR);
            }

            if (dceBuf.getAvailableLength() > 0)
                moreData[0] = true;
            else
                pipeFile.setBufferedData(null);

            return data;
        }
    }
}
