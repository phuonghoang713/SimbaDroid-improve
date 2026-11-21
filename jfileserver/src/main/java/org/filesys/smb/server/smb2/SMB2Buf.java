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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Growable little-endian output buffer used to build SMB2 responses.
 */
public final class SMB2Buf {

    private byte[] m_buf;
    private int m_pos;

    public SMB2Buf(int capacity) {
        m_buf = new byte[Math.max(capacity, 64)];
    }

    public byte[] array() {
        return m_buf;
    }

    public int position() {
        return m_pos;
    }

    public void position(int pos) {
        ensureCapacity(pos);
        m_pos = pos;
    }

    /**
     * Make sure the buffer can hold at least the specified total number of bytes
     *
     * @param total int
     */
    public void ensureCapacity(int total) {
        if (total > m_buf.length) {
            int newLen = Math.max(total, m_buf.length + (m_buf.length >> 1));
            m_buf = Arrays.copyOf(m_buf, newLen);
        }
    }

    public void ensureAvailable(int extra) {
        ensureCapacity(m_pos + extra);
    }

    public void putByte(int val) {
        ensureAvailable(1);
        m_buf[m_pos++] = (byte) val;
    }

    public void putShort(int val) {
        ensureAvailable(2);
        m_buf[m_pos++] = (byte) val;
        m_buf[m_pos++] = (byte) (val >> 8);
    }

    public void putInt(int val) {
        ensureAvailable(4);
        m_buf[m_pos++] = (byte) val;
        m_buf[m_pos++] = (byte) (val >> 8);
        m_buf[m_pos++] = (byte) (val >> 16);
        m_buf[m_pos++] = (byte) (val >> 24);
    }

    public void putLong(long val) {
        putInt((int) val);
        putInt((int) (val >>> 32));
    }

    public void putBytes(byte[] src) {
        putBytes(src, 0, src.length);
    }

    public void putBytes(byte[] src, int off, int len) {
        ensureAvailable(len);
        System.arraycopy(src, off, m_buf, m_pos, len);
        m_pos += len;
    }

    public void putZeros(int cnt) {
        ensureAvailable(cnt);
        Arrays.fill(m_buf, m_pos, m_pos + cnt, (byte) 0);
        m_pos += cnt;
    }

    /**
     * Write a string as UTF-16LE without a terminator
     *
     * @param str String
     * @return int Number of bytes written
     */
    public int putUnicode(String str) {
        byte[] byts = str.getBytes(StandardCharsets.UTF_16LE);
        putBytes(byts);
        return byts.length;
    }

    /**
     * Pad with zeros so that (position - base) is a multiple of the alignment
     *
     * @param base  int
     * @param align int
     */
    public void align(int base, int align) {
        int rem = (m_pos - base) % align;
        if (rem != 0)
            putZeros(align - rem);
    }

    public void setShortAt(int pos, int val) {
        m_buf[pos] = (byte) val;
        m_buf[pos + 1] = (byte) (val >> 8);
    }

    public void setIntAt(int pos, int val) {
        m_buf[pos] = (byte) val;
        m_buf[pos + 1] = (byte) (val >> 8);
        m_buf[pos + 2] = (byte) (val >> 16);
        m_buf[pos + 3] = (byte) (val >> 24);
    }

    public void setLongAt(int pos, long val) {
        setIntAt(pos, (int) val);
        setIntAt(pos + 4, (int) (val >>> 32));
    }

    // Static little-endian readers

    public static int getShort(byte[] buf, int pos) {
        return (buf[pos] & 0xFF) | ((buf[pos + 1] & 0xFF) << 8);
    }

    public static int getInt(byte[] buf, int pos) {
        return (buf[pos] & 0xFF) | ((buf[pos + 1] & 0xFF) << 8) | ((buf[pos + 2] & 0xFF) << 16) | ((buf[pos + 3] & 0xFF) << 24);
    }

    public static long getLong(byte[] buf, int pos) {
        return (getInt(buf, pos) & 0xFFFFFFFFL) | ((long) getInt(buf, pos + 4) << 32);
    }

    public static String getUnicode(byte[] buf, int pos, int byteLen) {
        return new String(buf, pos, byteLen, StandardCharsets.UTF_16LE);
    }
}
