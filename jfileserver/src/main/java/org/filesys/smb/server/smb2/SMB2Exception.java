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

/**
 * Exception carrying an NT status code, used to fail an SMB2 request.
 */
public class SMB2Exception extends Exception {

    private static final long serialVersionUID = 1L;

    private final int m_status;
    private byte[] m_errorData;

    public SMB2Exception(int status) {
        super("NT status 0x" + Integer.toHexString(status));
        m_status = status;
    }

    /**
     * Create an exception that returns additional data in the error response, for example the buffer size
     * required for STATUS_BUFFER_TOO_SMALL
     *
     * @param status    int
     * @param errorData byte[]
     */
    public SMB2Exception(int status, byte[] errorData) {
        this(status);
        m_errorData = errorData;
    }

    public SMB2Exception(int status, String msg) {
        super(msg);
        m_status = status;
    }

    public final int getStatus() {
        return m_status;
    }

    public final byte[] getErrorData() {
        return m_errorData;
    }
}
