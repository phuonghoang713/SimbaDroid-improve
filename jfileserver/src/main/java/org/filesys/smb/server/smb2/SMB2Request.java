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

import org.filesys.server.filesys.TreeConnection;

/**
 * A single SMB2 request within a received packet, with accessors for the header fields.
 */
public final class SMB2Request {

    public static final long RELATED_ID = 0xFFFFFFFFFFFFFFFFL;

    private final byte[] m_buf;
    private final int m_off;
    private final int m_len;
    private final boolean m_encrypted;

    // Values resolved by the protocol handler before the command handler is called
    long sessionId;
    int treeId;
    SMB2Session session;
    TreeConnection tree;
    boolean signed;

    // File id of the open created/used by the previous request of a compound chain, and the status of the create
    // request of the chain if it failed
    long relatedFileId = RELATED_ID;
    int chainError;
    boolean lastInChain = true;

    // Values set by the command handler
    long usedFileId = RELATED_ID;
    long pendingAsyncId;
    boolean signResponse;
    SMB2Session preauthSession;

    /**
     * Class constructor
     *
     * @param buf       byte[] Buffer holding the request
     * @param off       int Offset of the SMB2 header
     * @param len       int Length of the request, including the header
     * @param encrypted boolean true if the request was received encrypted
     */
    public SMB2Request(byte[] buf, int off, int len, boolean encrypted) {
        m_buf = buf;
        m_off = off;
        m_len = len;
        m_encrypted = encrypted;

        sessionId = SMB2Buf.getLong(buf, off + SMB2.OFF_SESSION_ID);
        treeId = SMB2Buf.getInt(buf, off + SMB2.OFF_TREE_ID);
    }

    public byte[] buffer() {
        return m_buf;
    }

    /**
     * Return the offset of the SMB2 header within the buffer
     *
     * @return int
     */
    public int offset() {
        return m_off;
    }

    /**
     * Return the offset of the request body, following the header
     *
     * @return int
     */
    public int body() {
        return m_off + SMB2.HEADER_LEN;
    }

    public int length() {
        return m_len;
    }

    public int bodyLength() {
        return m_len - SMB2.HEADER_LEN;
    }

    public boolean isEncrypted() {
        return m_encrypted;
    }

    public int command() {
        return SMB2Buf.getShort(m_buf, m_off + SMB2.OFF_COMMAND);
    }

    public int flags() {
        return SMB2Buf.getInt(m_buf, m_off + SMB2.OFF_FLAGS);
    }

    public boolean hasFlag(int flag) {
        return (flags() & flag) != 0;
    }

    public int creditCharge() {
        return SMB2Buf.getShort(m_buf, m_off + SMB2.OFF_CREDIT_CHARGE);
    }

    public int creditRequest() {
        return SMB2Buf.getShort(m_buf, m_off + SMB2.OFF_CREDITS);
    }

    public long messageId() {
        return SMB2Buf.getLong(m_buf, m_off + SMB2.OFF_MESSAGE_ID);
    }

    public long asyncId() {
        return SMB2Buf.getLong(m_buf, m_off + SMB2.OFF_ASYNC_ID);
    }

    public int processId() {
        return SMB2Buf.getInt(m_buf, m_off + SMB2.OFF_PROCESS_ID);
    }

    // Body accessors, positions are relative to the start of the request body

    public int getByte(int pos) {
        return m_buf[body() + pos] & 0xFF;
    }

    public int getShort(int pos) {
        return SMB2Buf.getShort(m_buf, body() + pos);
    }

    public int getInt(int pos) {
        return SMB2Buf.getInt(m_buf, body() + pos);
    }

    public long getLong(int pos) {
        return SMB2Buf.getLong(m_buf, body() + pos);
    }

    /**
     * Check that the request body is at least the specified length and has the expected structure size
     *
     * @param structSize int Expected StructureSize value
     * @param minLen     int Minimum length of the fixed part of the body
     * @exception SMB2Exception Invalid request
     */
    public void checkBody(int structSize, int minLen)
            throws SMB2Exception {
        if (bodyLength() < minLen || getShort(0) != structSize)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
    }

    /**
     * Validate a variable length buffer that is addressed by an offset from the start of the SMB2 header, returning
     * the absolute offset of the data within the request buffer.
     *
     * @param hdrOff int Offset from the start of the SMB2 header
     * @param len    int Length of the data
     * @return int Absolute buffer offset
     * @exception SMB2Exception Buffer is not within the request
     */
    public int checkRange(int hdrOff, int len)
            throws SMB2Exception {
        if (len < 0 || hdrOff < SMB2.HEADER_LEN || hdrOff > m_len || len > m_len - hdrOff)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
        return m_off + hdrOff;
    }

    /**
     * Return the file id from the request, resolving the related operations placeholder value
     *
     * @param pos int Position of the 16 byte file id within the request body
     * @return long Volatile file id
     */
    public long fileId(int pos) {
        long persistent = getLong(pos);
        long volatileId = getLong(pos + 8);

        if (persistent == RELATED_ID && volatileId == RELATED_ID)
            return relatedFileId;
        return volatileId;
    }
}
