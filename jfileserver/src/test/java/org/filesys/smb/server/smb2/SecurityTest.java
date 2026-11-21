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
import static org.junit.Assert.fail;

import java.util.List;

import org.filesys.server.auth.LogonThrottle;
import org.filesys.smb.server.nio.NIOSMBConnectionsHandler;
import org.junit.Test;

import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;

/**
 * Tests of the measures that protect the server against misuse.
 */
public class SecurityTest {

    private static final long STATUS_LOGON_FAILURE = 0xC000006DL;
    private static final long STATUS_ACCESS_DENIED = 0xC0000022L;
    private static final int STATUS_INSUFFICIENT_RESOURCES = 0xC000009A;

    private static long logon(TestSmbServer server, AuthenticationContext ac) throws Exception {
        SmbConfig config = SmbConfig.builder().withDfsEnabled(false).build();

        try (SMBClient client = new SMBClient(config); Connection conn = client.connect("127.0.0.1", server.getPort())) {
            Session session = conn.authenticate(ac);
            try (DiskShare share = (DiskShare) session.connectShare(TestSmbServer.SHARE)) {
                share.list("");
            }
            return 0;
        }
        catch (SMBApiException ex) {
            return ex.getStatusCode();
        }
    }

    private static AuthenticationContext user(String password) {
        return new AuthenticationContext(TestSmbServer.USER, password.toCharArray(), "WORKGROUP");
    }

    @Test
    public void passwordGuessingIsThrottled() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.user())) {
            assertEquals(0, logon(server, user(TestSmbServer.PASSWORD)));

            for (int i = 0; i < LogonThrottle.DefaultMaxFailures; i++)
                assertEquals(STATUS_LOGON_FAILURE, logon(server, user("guess" + i)));

            // Even the right password is refused now
            assertEquals(STATUS_LOGON_FAILURE, logon(server, user(TestSmbServer.PASSWORD)));
        }
    }

    @Test
    public void aFewWrongPasswordsDoNotLockTheUserOut() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.user())) {
            for (int i = 0; i < 5; i++)
                assertEquals(STATUS_LOGON_FAILURE, logon(server, user("guess" + i)));

            assertEquals(0, logon(server, user(TestSmbServer.PASSWORD)));
        }
    }

    @Test
    public void anonymousAndUnknownUsersAreRefusedWhenALoginIsRequired() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.user())) {
            assertEquals(STATUS_ACCESS_DENIED, logon(server, AuthenticationContext.anonymous()));
            assertEquals(STATUS_LOGON_FAILURE, logon(server, new AuthenticationContext("someone", "x".toCharArray(), "")));
        }
    }

    @Test
    public void unsignedRequestsAreRefusedWhenSigningIsRequired() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.user().requireSigning())) {
            // smbj signs because the server asks for it
            assertEquals(0, logon(server, user(TestSmbServer.PASSWORD)));
        }
    }

    /**
     * A single packet with hundreds of read requests must not make the server build a response of hundreds of
     * megabytes.
     */
    @Test
    public void compoundResponsesAreLimited() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.guest());
             RawProtocolTest.Client c = RawProtocolTest.session(server.getPort())) {

            String name = "flood.bin";
            byte[] block = new byte[60000];

            RawProtocolTest.Msg m = c.call(5, RawProtocolTest.createBody(name, 0x0012019F, 3, 0));
            assertEquals(0, m.status);
            long fid = m.i64(64 + 8);
            assertEquals(0, c.call(9, RawProtocolTest.writeBody(fid, 0, block)).status);

            int reads = 400;
            byte[][] requests = new byte[reads][];
            for (int i = 0; i < reads; i++)
                requests[i] = c.request(8, 0, readBody(fid, 0, block.length));

            c.sendRaw(c.compound(false, requests));
            byte[] raw = c.recvRaw();

            assertTrue("response size " + raw.length, raw.length < 2 * 1024 * 1024);

            // The first reads succeed, the rest are refused, and every request gets an answer
            List<RawProtocolTest.Msg> responses = RawProtocolTest.parse(raw);
            assertEquals(reads, responses.size());
            assertEquals(0, responses.get(0).status);
            assertEquals(STATUS_INSUFFICIENT_RESOURCES, responses.get(reads - 1).status);

            // The connection is still usable
            assertEquals(0, c.call(6, RawProtocolTest.closeBody(fid)).status);
        }
        catch (java.io.IOException ex) {
            fail("Server dropped the connection: " + ex);
        }
    }

    /**
     * The number of simultaneous connections is limited, and the server recovers once they are closed.
     */
    @Test
    public void connectionsAreLimited() throws Exception {
        try (TestSmbServer server = new TestSmbServer(TestSmbServer.Options.guest())) {
            int count = NIOSMBConnectionsHandler.MaxConnections + 60;
            java.util.List<java.net.Socket> sockets = new java.util.ArrayList<java.net.Socket>();

            try {
                for (int i = 0; i < count; i++) {
                    java.net.Socket sock = new java.net.Socket("127.0.0.1", server.getPort());
                    sock.setSoTimeout(100);
                    sockets.add(sock);
                    // Give the server a moment to register the connections now and then
                    if (i % 50 == 49)
                        Thread.sleep(100);
                }
                Thread.sleep(300);

                // Connections over the limit have been closed by the server
                int refused = 0;
                for (java.net.Socket sock : sockets) {
                    try {
                        if (sock.getInputStream().read() == -1)
                            refused++;
                    }
                    catch (java.net.SocketTimeoutException ex) {
                        // Still open
                    }
                    catch (java.io.IOException ex) {
                        refused++;
                    }
                }
                assertTrue("refused " + refused, refused >= 30);
            }
            finally {
                for (java.net.Socket sock : sockets)
                    sock.close();
            }

            // Once the connections have gone the server accepts clients again
            long deadline = System.currentTimeMillis() + 10000L;
            long status = -1;
            while (status != 0 && System.currentTimeMillis() < deadline) {
                try {
                    status = logon(server, new AuthenticationContext("someone", "x".toCharArray(), ""));
                }
                catch (Exception ex) {
                    Thread.sleep(200);
                }
            }
            assertEquals(0, status);
        }
    }

    private static byte[] readBody(long fid, long offset, int length) {
        java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(49).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 49).put((byte) 0).put((byte) 0).putInt(length).putLong(offset).putLong(fid).putLong(fid)
                .putInt(0).putInt(0).putInt(0).putShort((short) 0).putShort((short) 0).put((byte) 0);
        return bb.array();
    }
}
