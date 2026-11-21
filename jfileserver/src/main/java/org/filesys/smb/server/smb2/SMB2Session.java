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

import java.util.concurrent.ConcurrentHashMap;

import org.filesys.server.auth.ClientInfo;
import org.filesys.smb.server.VirtualCircuit;

/**
 * An SMB2 session, the authenticated context of a user on a connection.
 */
public final class SMB2Session {

    private final long m_id;

    // Authentication in progress
    SMB2Authenticator.Context authContext;

    // Set once the session has been authenticated
    volatile boolean valid;
    boolean guest;
    boolean anonymous;

    VirtualCircuit vc;
    ClientInfo client;

    // Keys, null for guest and anonymous sessions
    byte[] sessionKey;
    byte[] signingKey;
    byte[] encryptKey;
    byte[] decryptKey;

    boolean signingRequired;
    boolean encryptData;

    // Pre-authentication integrity hash, SMB 3.1.1
    byte[] preauthHash;

    // Open files, keyed by the volatile file id
    final ConcurrentHashMap<Long, SMB2Open> opens = new ConcurrentHashMap<Long, SMB2Open>();

    SMB2Session(long id) {
        m_id = id;
    }

    public long getId() {
        return m_id;
    }

    public boolean hasSigningKey() {
        return signingKey != null;
    }

    public boolean canEncrypt() {
        return encryptKey != null && decryptKey != null;
    }

    @Override
    public String toString() {
        return "[SMB2 session 0x" + Long.toHexString(m_id) + (client != null ? " user=" + client.getUserName() : "")
                + (guest ? " guest" : "") + (anonymous ? " anon" : "") + "]";
    }
}
