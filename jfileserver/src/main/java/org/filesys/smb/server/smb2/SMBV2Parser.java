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

import org.filesys.debug.Debug;
import org.filesys.netbios.RFCNetBIOSProtocol;
import org.filesys.server.auth.AuthenticatorException;
import org.filesys.server.locking.OpLockDetails;
import org.filesys.server.locking.OplockOwner;
import org.filesys.smb.Dialect;
import org.filesys.smb.DialectSelector;
import org.filesys.smb.SMBStatus;
import org.filesys.smb.server.NegotiateContext;
import org.filesys.smb.server.ProtocolHandler;
import org.filesys.smb.server.SMBParser;
import org.filesys.smb.server.SMBServer;
import org.filesys.smb.server.SMBSrvException;
import org.filesys.smb.server.SMBSrvPacket;
import org.filesys.smb.server.SMBSrvSession;
import org.filesys.smb.server.SessionState;

/**
 * SMB2/SMB3 packet parser.
 *
 * <p>The SMB2 protocol handler does its own request parsing and response building. This class provides the pieces
 * that the protocol independent session code requires: identifying the packet type, parsing the negotiate request
 * and building error responses.
 */
public class SMBV2Parser extends SMBParser {

    // Offset of the SMB2 header within the packet buffer
    private static final int HDR = RFCNetBIOSProtocol.HEADER_LEN;

    // Negotiate request body
    private static final int NEG_FIXED_LEN = 36;
    private static final int NEG_DIALECT_COUNT = 2;
    private static final int NEG_SECURITY_MODE = 4;
    private static final int NEG_CLIENT_GUID = 12;
    private static final int NEG_CONTEXT_OFFSET = 28;
    private static final int NEG_CONTEXT_COUNT = 32;

    private static final int MAX_DIALECTS = 64;
    private static final int MAX_CONTEXT_ITEMS = 32;

    // Length of a response that has been built in place, or -1
    private int m_respLen = -1;

    /**
     * Class constructor
     *
     * @param buf byte[]
     * @param len int
     */
    public SMBV2Parser(byte[] buf, int len) {
        super(buf, len);
    }

    public final int getCommand() {
        return SMB2Buf.getShort(m_smbbuf, HDR + SMB2.OFF_COMMAND);
    }

    public final int getStatus() {
        return SMB2Buf.getInt(m_smbbuf, HDR + SMB2.OFF_STATUS);
    }

    public final int getFlags() {
        return SMB2Buf.getInt(m_smbbuf, HDR + SMB2.OFF_FLAGS);
    }

    public final long getMessageId() {
        return SMB2Buf.getLong(m_smbbuf, HDR + SMB2.OFF_MESSAGE_ID);
    }

    private void putShort(int pos, int val) {
        m_smbbuf[pos] = (byte) val;
        m_smbbuf[pos + 1] = (byte) (val >> 8);
    }

    private void putInt(int pos, int val) {
        putShort(pos, val);
        putShort(pos + 2, val >> 16);
    }

    @Override
    public boolean checkPacketIsValid(int reqWords, int reqBytes) {
        return m_endpos >= HDR + SMB2.HEADER_LEN && m_smbbuf.length >= HDR + SMB2.HEADER_LEN
                && SMB2Buf.getShort(m_smbbuf, HDR + SMB2.OFF_STRUCT_SIZE) == SMB2.HEADER_LEN;
    }

    @Override
    public void dumpPacket(boolean dumpRaw, boolean dumpAll) {
        Debug.println(toShortString());
    }

    @Override
    public String getName() {
        return "SMB2";
    }

    @Override
    public SMBSrvPacket.Version isType() {
        return SMBSrvPacket.Version.V2;
    }

    @Override
    public int getLength() {
        if (m_respLen >= 0)
            return m_respLen;
        return Math.max(m_endpos - HDR, 0);
    }

    @Override
    public void packSuccessRespone() {
        buildErrorResponse(SMBStatus.NTErr, SMBStatus.NTSuccess, null);
    }

    @Override
    public void setResponse() {
        if (m_smbbuf.length >= HDR + SMB2.HEADER_LEN)
            putInt(HDR + SMB2.OFF_FLAGS, getFlags() | SMB2.FLG_SERVER_TO_REDIR);
    }

    @Override
    public String toShortString() {
        if (m_smbbuf.length < HDR + SMB2.HEADER_LEN)
            return "[SMB2 short packet]";
        return "[SMB2 " + SMB2.commandName(getCommand()) + " mid=" + getMessageId() + " sts=0x"
                + Integer.toHexString(getStatus()) + "]";
    }

    @Override
    public boolean isLongErrorCode() {
        return true;
    }

    @Override
    public int getErrorClass() {
        return SMBStatus.NTErr;
    }

    @Override
    public int getErrorCode() {
        return getStatus();
    }

    @Override
    public SessionState nextStateForDialect(int dialectId) {

        // A wildcard SMB2 dialect response to an SMB1 negotiate is followed by an SMB2 negotiate
        if (dialectId == Dialect.SMB2_Any)
            return SessionState.SMB_NEGOTIATE;
        return SessionState.SMB_SESSION;
    }

    /**
     * Build an error response in place, re-using the header of the request. This is only used for errors raised
     * by the protocol independent session code, before or during the negotiate phase.
     */
    @Override
    public void buildErrorResponse(int errClass, int errCode, ProtocolHandler protocolHandler) {
        if (m_smbbuf.length < HDR + SMB2.HEADER_LEN + 9)
            return;

        int status = errClass == SMBStatus.NTErr ? errCode : SMB2.STATUS_UNSUCCESSFUL;

        putInt(HDR + SMB2.OFF_STATUS, status);
        putShort(HDR + SMB2.OFF_CREDITS, 1);
        putInt(HDR + SMB2.OFF_FLAGS, SMB2.FLG_SERVER_TO_REDIR);
        putInt(HDR + SMB2.OFF_NEXT_COMMAND, 0);

        for (int i = 0; i < SMB2.SIGNATURE_LEN; i++)
            m_smbbuf[HDR + SMB2.OFF_SIGNATURE + i] = 0;

        // Error response body
        int pos = HDR + SMB2.HEADER_LEN;
        putShort(pos, 9);
        for (int i = 2; i < 9; i++)
            m_smbbuf[pos + i] = 0;

        m_respLen = SMB2.HEADER_LEN + 9;
    }

    @Override
    public NegotiateContext parseNegotiateRequest(SMBSrvSession sess)
            throws SMBSrvException {

        int body = HDR + SMB2.HEADER_LEN;

        if (!checkPacketIsValid(0, 0) || getCommand() != SMB2.CMD_NEGOTIATE || m_endpos < body + NEG_FIXED_LEN
                || SMB2Buf.getShort(m_smbbuf, body) != NEG_FIXED_LEN)
            throw new SMBSrvException(SMBStatus.NTInvalidParameter);

        int dialectCnt = SMB2Buf.getShort(m_smbbuf, body + NEG_DIALECT_COUNT);
        if (dialectCnt == 0 || dialectCnt > MAX_DIALECTS || body + NEG_FIXED_LEN + (dialectCnt * 2) > m_endpos)
            throw new SMBSrvException(SMBStatus.NTInvalidParameter);

        DialectSelector dialects = new DialectSelector();
        int[] revisions = new int[dialectCnt];
        boolean smb311 = false;

        for (int i = 0; i < dialectCnt; i++) {
            int rev = SMB2Buf.getShort(m_smbbuf, body + NEG_FIXED_LEN + (i * 2));
            revisions[i] = rev;

            // The wildcard revision is only valid in the response to a multi-protocol negotiate
            if (rev == SMB2.DIALECT_WILDCARD)
                continue;

            int dialectId = Dialect.SMB2DialectToId(rev);
            if (dialectId != -1)
                dialects.AddDialect(dialectId);
            if (rev == SMB2.DIALECT_311)
                smb311 = true;
        }

        SMB2NegotiateContext negCtx = new SMB2NegotiateContext(dialects);
        negCtx.setDialectRevisions(revisions);
        negCtx.setSecurityMode(SMB2Buf.getShort(m_smbbuf, body + NEG_SECURITY_MODE));
        negCtx.setCapabilities(SMB2Buf.getInt(m_smbbuf, body + 8));

        byte[] guid = new byte[16];
        System.arraycopy(m_smbbuf, body + NEG_CLIENT_GUID, guid, 0, 16);
        negCtx.setClientGuid(guid);

        if (smb311)
            parseNegotiateContexts(negCtx, body);

        return negCtx;
    }

    /**
     * Parse the SMB 3.1.1 negotiate context list
     *
     * @param negCtx SMB2NegotiateContext
     * @param body   int
     * @exception SMBSrvException Invalid context list
     */
    private void parseNegotiateContexts(SMB2NegotiateContext negCtx, int body)
            throws SMBSrvException {

        int ctxOff = SMB2Buf.getInt(m_smbbuf, body + NEG_CONTEXT_OFFSET);
        int ctxCnt = SMB2Buf.getShort(m_smbbuf, body + NEG_CONTEXT_COUNT);

        if (ctxCnt == 0)
            return;
        if (ctxOff < SMB2.HEADER_LEN + NEG_FIXED_LEN || ctxOff > m_endpos - HDR)
            throw new SMBSrvException(SMBStatus.NTInvalidParameter);

        int pos = HDR + ctxOff;

        for (int i = 0; i < ctxCnt; i++) {

            // Contexts are aligned on 8 byte boundaries, relative to the start of the SMB2 header
            pos = HDR + (((pos - HDR) + 7) & ~7);
            if (pos + 8 > m_endpos)
                throw new SMBSrvException(SMBStatus.NTInvalidParameter);

            int ctxType = SMB2Buf.getShort(m_smbbuf, pos);
            int dataLen = SMB2Buf.getShort(m_smbbuf, pos + 2);
            int data = pos + 8;

            if (data + dataLen > m_endpos)
                throw new SMBSrvException(SMBStatus.NTInvalidParameter);

            switch (ctxType) {
                case SMB2.CTX_PREAUTH_INTEGRITY: {
                    if (dataLen < 4)
                        throw new SMBSrvException(SMBStatus.NTInvalidParameter);
                    int[] algs = readIdList(data, 4, dataLen);
                    for (int alg : algs) {
                        if (alg == SMB2.HASH_SHA512)
                            negCtx.setPreauthSHA512(true);
                    }
                    break;
                }
                case SMB2.CTX_ENCRYPTION:
                    if (dataLen < 2)
                        throw new SMBSrvException(SMBStatus.NTInvalidParameter);
                    negCtx.setCiphers(readIdList(data, 2, dataLen));
                    break;
                case SMB2.CTX_SIGNING:
                    if (dataLen < 2)
                        throw new SMBSrvException(SMBStatus.NTInvalidParameter);
                    negCtx.setSigningAlgorithms(readIdList(data, 2, dataLen));
                    break;
                default:
                    // Unknown contexts are ignored
                    break;
            }

            pos = data + dataLen;
        }
    }

    /**
     * Read a counted list of 16 bit identifiers from a negotiate context
     *
     * @param data    int Offset of the context data, the count is the first field
     * @param listOff int Offset of the list within the context data
     * @param dataLen int
     * @return int[]
     * @exception SMBSrvException Invalid list
     */
    private int[] readIdList(int data, int listOff, int dataLen)
            throws SMBSrvException {
        int cnt = SMB2Buf.getShort(m_smbbuf, data);
        if (cnt > MAX_CONTEXT_ITEMS || listOff + (cnt * 2) > dataLen)
            throw new SMBSrvException(SMBStatus.NTInvalidParameter);

        int[] ids = new int[cnt];
        for (int i = 0; i < cnt; i++)
            ids[i] = SMB2Buf.getShort(m_smbbuf, data + listOff + (i * 2));
        return ids;
    }

    @Override
    public void packNegotiateResponse(SMBServer server, SMBSrvSession sess, SMBSrvPacket smbPkt, int selDialect,
                                      NegotiateContext negCtx)
            throws AuthenticatorException, SMBSrvException {

        // The response is built by the protocol handler, which holds the connection state
        ProtocolHandler handler = sess.getProtocolHandler();
        if (!(handler instanceof SMB2ProtocolHandler))
            throw new SMBSrvException(SMBStatus.NTNotSupported);

        m_respLen = ((SMB2ProtocolHandler) handler).packNegotiateResponse(smbPkt, selDialect, negCtx);
    }

    @Override
    public OplockOwner createOplockOwner(SMBSrvSession sess, int vcId, OpLockDetails opLock) {

        // Oplocks are not granted to SMB2 clients
        return null;
    }
}
