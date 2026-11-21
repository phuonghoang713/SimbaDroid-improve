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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.EnumSet;

import org.junit.Test;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;

/**
 * Tests that the server can be stopped and started again using the same configuration, as the app does each time
 * the network connection changes.
 */
public class ServerLifecycleTest {

    private static int listFiles(TestSmbServer server) throws Exception {
        SmbConfig config = SmbConfig.builder().withDfsEnabled(false).build();

        try (SMBClient client = new SMBClient(config); Connection conn = client.connect("127.0.0.1", server.getPort())) {
            Session session = conn.authenticate(new AuthenticationContext("someone", "x".toCharArray(), ""));
            try (DiskShare share = (DiskShare) session.connectShare(TestSmbServer.SHARE)) {
                return share.list("").size();
            }
        }
    }

    @Test
    public void serverCanBeRestarted() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.guest())) {
            int entries = listFiles(server);
            assertTrue(entries >= 2);

            for (int i = 0; i < 15; i++) {
                server.stop();
                server.start();
                assertEquals("after restart " + i, entries, listFiles(server));
            }
        }
    }

    @Test
    public void restartWithAClientConnected() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.guest())) {
            SmbConfig config = SmbConfig.builder().withDfsEnabled(false).build();
            SMBClient client = new SMBClient(config);
            Connection conn = client.connect("127.0.0.1", server.getPort());
            Session session = conn.authenticate(new AuthenticationContext("someone", "x".toCharArray(), ""));
            DiskShare share = (DiskShare) session.connectShare(TestSmbServer.SHARE);

            // Leave a file open with unwritten state when the server stops
            File file = share.openFile("left_open.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OVERWRITE_IF, null);
            file.write(new byte[]{1, 2, 3}, 0);

            server.stop();
            server.start();

            try {
                conn.close(true);
            }
            catch (Exception ex) {
                // The connection was dropped by the server
            }
            client.close();

            assertTrue(listFiles(server) >= 3);
            assertEquals(3L, new java.io.File(server.getShareDirectory(), "left_open.txt").length());
        }
    }
}
