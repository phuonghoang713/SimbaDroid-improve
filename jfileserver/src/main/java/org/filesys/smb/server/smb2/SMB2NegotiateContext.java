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

import org.filesys.smb.DialectSelector;
import org.filesys.smb.server.NegotiateContext;

/**
 * Details of an SMB2 negotiate request.
 */
public final class SMB2NegotiateContext extends NegotiateContext {

    // Dialect revisions offered by the client, in the order sent
    private int[] m_dialectRevisions = new int[0];

    private int m_securityMode;
    private byte[] m_clientGuid = new byte[16];

    // SMB 3.1.1 negotiate contexts
    private boolean m_preauthSHA512;
    private int[] m_ciphers = new int[0];
    private int[] m_signingAlgorithms = new int[0];

    public SMB2NegotiateContext(DialectSelector dialects) {
        super(dialects);
    }

    public int[] getDialectRevisions() {
        return m_dialectRevisions;
    }

    void setDialectRevisions(int[] revisions) {
        m_dialectRevisions = revisions;
    }

    public int getSecurityMode() {
        return m_securityMode;
    }

    void setSecurityMode(int secMode) {
        m_securityMode = secMode;
    }

    public byte[] getClientGuid() {
        return m_clientGuid;
    }

    void setClientGuid(byte[] guid) {
        m_clientGuid = guid;
    }

    public boolean hasPreauthSHA512() {
        return m_preauthSHA512;
    }

    void setPreauthSHA512(boolean sha512) {
        m_preauthSHA512 = sha512;
    }

    public int[] getCiphers() {
        return m_ciphers;
    }

    void setCiphers(int[] ciphers) {
        m_ciphers = ciphers;
    }

    public boolean hasCipher(int cipherId) {
        for (int cipher : m_ciphers) {
            if (cipher == cipherId)
                return true;
        }
        return false;
    }

    public int[] getSigningAlgorithms() {
        return m_signingAlgorithms;
    }

    void setSigningAlgorithms(int[] algs) {
        m_signingAlgorithms = algs;
    }

    public boolean hasSigningAlgorithm(int algId) {
        for (int alg : m_signingAlgorithms) {
            if (alg == algId)
                return true;
        }
        return false;
    }
}
