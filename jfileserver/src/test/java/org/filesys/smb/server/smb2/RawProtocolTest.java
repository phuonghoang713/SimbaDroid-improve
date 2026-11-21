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

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Protocol level tests using hand built SMB2 messages, for the parts of the protocol that client libraries do not
 * expose: compounded requests, the upgrade from an SMB1 negotiate, error handling and malformed requests.
 */
public class RawProtocolTest {

    private static final int FUZZ_ITERATIONS = 1500;

    private static TestSmbServer server;

    @BeforeClass
    public static void startServer() throws Exception {
        server = new TestSmbServer(TestSmbServer.Options.guest());
    }

    @AfterClass
    public static void stopServer() {
        server.close();
    }

    private static void check(boolean cond, String what) {
        assertTrue(what, cond);
    }

    @Test
    public void compoundRequests() throws Exception {
        testCompound(server.getPort());
    }

    @Test
    public void negotiateFromSmb1() throws Exception {
        testSmb1Negotiate(server.getPort());
    }

    @Test
    public void errorHandling() throws Exception {
        testMisc(server.getPort());
    }

    @Test
    public void malformedRequestsDoNotBreakTheServer() throws Exception {
        testFuzz(server.getPort(), FUZZ_ITERATIONS);
    }

    static class Msg {
        int status, command, flags, next, credits;
        long messageId, sessionId;
        int treeId;
        byte[] raw;
        int off;

        int u16(int pos) { return ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).getShort(off + pos) & 0xFFFF; }
        int i32(int pos) { return ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).getInt(off + pos); }
        long i64(int pos) { return ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).getLong(off + pos); }
    }

    /**
     * Split a received packet into its chained responses
     */
    static List<Msg> parse(byte[] raw) {
        List<Msg> list = new ArrayList<Msg>();
        int off = 0;
        while (true) {
            ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
            Msg m = new Msg();
            m.raw = raw;
            m.off = off + 64;
            m.status = bb.getInt(off + 8);
            m.command = bb.getShort(off + 12) & 0xFFFF;
            m.credits = bb.getShort(off + 14) & 0xFFFF;
            m.flags = bb.getInt(off + 16);
            m.next = bb.getInt(off + 20);
            m.messageId = bb.getLong(off + 24);
            m.treeId = bb.getInt(off + 36);
            m.sessionId = bb.getLong(off + 40);
            list.add(m);
            if (m.next == 0)
                break;
            off += m.next;
        }
        return list;
    }

    static class Client implements AutoCloseable {
        Socket sock;
        DataInputStream in;
        OutputStream out;
        long msgId = 0;
        long sessionId = 0;
        int treeId = 0;

        Client(int port) throws IOException {
            sock = new Socket("127.0.0.1", port);
            sock.setSoTimeout(5000);
            in = new DataInputStream(sock.getInputStream());
            out = sock.getOutputStream();
        }

        public void close() {
            try { sock.close(); } catch (IOException ex) { }
        }

        void sendRaw(byte[] msg) throws IOException {
            ByteBuffer bb = ByteBuffer.allocate(4 + msg.length);
            bb.putInt(msg.length);
            bb.put(msg);
            out.write(bb.array());
            out.flush();
        }

        byte[] recvRaw() throws IOException {
            int len = in.readInt() & 0x00FFFFFF;
            byte[] buf = new byte[len];
            in.readFully(buf);
            return buf;
        }

        List<Msg> recv() throws IOException {
            return parse(recvRaw());
        }

        byte[] header(int cmd, int flags, long treeIdVal, long sessId) {
            ByteBuffer bb = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) 0xFE).put((byte) 'S').put((byte) 'M').put((byte) 'B');
            bb.putShort((short) 64);
            bb.putShort((short) 1);          // credit charge
            bb.putInt(0);
            bb.putShort((short) cmd);
            bb.putShort((short) 16);         // credits requested
            bb.putInt(flags);
            bb.putInt(0);                    // next
            bb.putLong(msgId++);
            bb.putInt(0xFEFF);
            bb.putInt((int) treeIdVal);
            bb.putLong(sessId);
            return bb.array();
        }

        byte[] request(int cmd, int flags, byte[] body) {
            byte[] hdr = header(cmd, flags, treeId, sessionId);
            byte[] msg = new byte[64 + body.length];
            System.arraycopy(hdr, 0, msg, 0, 64);
            System.arraycopy(body, 0, msg, 64, body.length);
            return msg;
        }

        Msg call(int cmd, byte[] body) throws IOException {
            sendRaw(request(cmd, 0, body));
            return recv().get(0);
        }

        // Chain several requests into a compound, the first is unrelated and the rest related
        byte[] compound(boolean related, byte[]... msgs) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for (int i = 0; i < msgs.length; i++) {
                byte[] m = msgs[i];
                int padded = (m.length + 7) & ~7;
                byte[] p = new byte[i + 1 < msgs.length ? padded : m.length];
                System.arraycopy(m, 0, p, 0, m.length);
                ByteBuffer bb = ByteBuffer.wrap(p).order(ByteOrder.LITTLE_ENDIAN);
                if (i + 1 < msgs.length)
                    bb.putInt(20, padded);
                if (related && i > 0)
                    bb.putInt(16, bb.getInt(16) | 0x04);
                bos.write(p, 0, p.length);
            }
            return bos.toByteArray();
        }

        void negotiate(int... dialects) throws IOException {
            ByteBuffer bb = ByteBuffer.allocate(36 + dialects.length * 2).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 36).putShort((short) dialects.length).putShort((short) 1).putShort((short) 0);
            bb.putInt(0);
            bb.put(new byte[16]);
            bb.putLong(0);
            for (int d : dialects)
                bb.putShort((short) d);
            Msg m = call(0, bb.array());
            if (m.status != 0)
                throw new IOException("negotiate failed 0x" + Integer.toHexString(m.status));
        }

        void anonymousSession() throws IOException {
            // NTLMSSP negotiate
            ByteBuffer t1 = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN);
            t1.put("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII)).putInt(1).putInt(0x00088207);
            Msg m = call(1, sessionSetupBody(t1.array()));
            if (m.status != 0xC0000016)
                throw new IOException("session setup 1 failed 0x" + Integer.toHexString(m.status));
            sessionId = m.sessionId;

            // Anonymous authenticate
            ByteBuffer t3 = ByteBuffer.allocate(72).order(ByteOrder.LITTLE_ENDIAN);
            t3.put("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII)).putInt(3);
            for (int i = 0; i < 6; i++)
                t3.putShort((short) 0).putShort((short) 0).putInt(72);
            t3.putInt(0x00088a05);
            m = call(1, sessionSetupBody(t3.array()));
            if (m.status != 0)
                throw new IOException("session setup 2 failed 0x" + Integer.toHexString(m.status));
        }

        byte[] sessionSetupBody(byte[] token) {
            ByteBuffer bb = ByteBuffer.allocate(24 + token.length).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 25).put((byte) 0).put((byte) 1).putInt(0).putInt(0);
            bb.putShort((short) 88).putShort((short) token.length).putLong(0);
            bb.put(token);
            return bb.array();
        }

        void treeConnect(String path) throws IOException {
            byte[] p = path.getBytes(StandardCharsets.UTF_16LE);
            ByteBuffer bb = ByteBuffer.allocate(8 + p.length).order(ByteOrder.LITTLE_ENDIAN);
            bb.putShort((short) 9).putShort((short) 0).putShort((short) 72).putShort((short) p.length).put(p);
            Msg m = call(3, bb.array());
            if (m.status != 0)
                throw new IOException("tree connect failed 0x" + Integer.toHexString(m.status));
            treeId = m.treeId;
        }
    }

    static byte[] createBody(String name, int access, int disposition, int options) {
        byte[] n = name.getBytes(StandardCharsets.UTF_16LE);
        ByteBuffer bb = ByteBuffer.allocate(56 + Math.max(n.length, 1)).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 57).put((byte) 0).put((byte) 0).putInt(2).putLong(0).putLong(0);
        bb.putInt(access).putInt(0).putInt(7).putInt(disposition).putInt(options);
        bb.putShort((short) 120).putShort((short) n.length).putInt(0).putInt(0);
        bb.put(n);
        return bb.array();
    }

    static byte[] closeBody(long fid) {
        ByteBuffer bb = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 24).putShort((short) 1).putInt(0).putLong(fid).putLong(fid);
        return bb.array();
    }

    static byte[] queryInfoBody(long fid, int infoType, int infoClass, int outLen) {
        ByteBuffer bb = ByteBuffer.allocate(41).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 41).put((byte) infoType).put((byte) infoClass).putInt(outLen).putShort((short) 0).putShort((short) 0)
                .putInt(0).putInt(0).putInt(0).putLong(fid).putLong(fid);
        return bb.array();
    }

    static byte[] writeBody(long fid, long offset, byte[] data) {
        ByteBuffer bb = ByteBuffer.allocate(48 + data.length).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 49).putShort((short) 112).putInt(data.length).putLong(offset).putLong(fid).putLong(fid)
                .putInt(0).putInt(0).putShort((short) 0).putShort((short) 0).putInt(0);
        bb.put(data);
        return bb.array();
    }

    static byte[] queryDirBody(long fid, int infoClass, String pattern, int outLen) {
        byte[] p = pattern.getBytes(StandardCharsets.UTF_16LE);
        ByteBuffer bb = ByteBuffer.allocate(32 + p.length).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) 33).put((byte) infoClass).put((byte) 0).putInt(0).putLong(fid).putLong(fid)
                .putShort((short) 96).putShort((short) p.length).putInt(outLen);
        bb.put(p);
        return bb.array();
    }

    static byte[] echoBody() {
        return new byte[]{4, 0, 0, 0};
    }

    static final long REL = -1L;

    static Client session(int port) throws IOException {
        Client c = new Client(port);
        c.negotiate(0x0202, 0x0210);
        c.anonymousSession();
        c.treeConnect("\\\\127.0.0.1\\Internal");
        return c;
    }

    static void testCompound(int port) throws Exception {
        try (Client c = session(port)) {
            String name = "raw_" + System.nanoTime() + ".txt";
            byte[] data = "compound write".getBytes(StandardCharsets.UTF_8);

            // Related: create + write + query info + close
            c.sendRaw(c.compound(true,
                    c.request(5, 0, createBody(name, 0x0012019F, 3, 0)),
                    c.request(9, 0, writeBody(REL, 0, data)),
                    c.request(16, 0, queryInfoBody(REL, 1, 5, 24)),
                    c.request(6, 0, closeBody(REL))));
            List<Msg> r = c.recv();
            check(r.size() == 4, "compound response count " + r.size());
            boolean ok = r.size() == 4;
            for (Msg m : r)
                ok &= m.status == 0;
            check(ok, "related compound create+write+queryinfo+close");
            if (r.size() == 4) {
                check(r.get(2).i64(8 + 8) == data.length, "file size via related query info = " + r.get(2).i64(16));
                check((r.get(1).flags & 0x04) != 0, "related flag set on chained responses");
                check(r.get(0).messageId + 1 == r.get(1).messageId, "message ids preserved");
            }

            // Related chain after a failed create
            c.sendRaw(c.compound(true,
                    c.request(5, 0, createBody("does_not_exist_" + name, 0x00120089, 1, 0)),
                    c.request(16, 0, queryInfoBody(REL, 1, 5, 24)),
                    c.request(6, 0, closeBody(REL))));
            r = c.recv();
            ok = r.size() == 3;
            for (Msg m : r)
                ok &= m.status == 0xC0000034;
            check(ok, "failed create propagates through related chain");

            // Unrelated compound
            c.sendRaw(c.compound(false, c.request(13, 0, echoBody()), c.request(13, 0, echoBody())));
            r = c.recv();
            check(r.size() == 2 && r.get(0).status == 0 && r.get(1).status == 0, "unrelated compound echo+echo");

            // Create + query directory x2 + close, as Windows Explorer does
            c.sendRaw(c.compound(true,
                    c.request(5, 0, createBody("", 0x00100081, 1, 1)),
                    c.request(14, 0, queryDirBody(REL, 37, "*", 65536)),
                    c.request(14, 0, queryDirBody(REL, 37, "*", 65536))));
            r = c.recv();
            check(r.size() == 3 && r.get(0).status == 0 && r.get(1).status == 0
                    && (r.get(2).status == 0 || r.get(2).status == 0x80000006), "create + query directory compound (0x"
                    + Integer.toHexString(r.size() == 3 ? r.get(2).status : -1) + ")");
            long dirFid = r.get(0).i64(64 + 8);
            Msg m = c.call(6, closeBody(dirFid));
            check(m.status == 0, "close directory by id");

            // Related request as the first in a chain is invalid
            byte[] first = c.request(13, 0x04, echoBody());
            c.sendRaw(first);
            // echo does not check the flag, use a query info instead
            c.recv();
            c.sendRaw(c.request(16, 0x04, queryInfoBody(REL, 1, 5, 24)));
            m = c.recv().get(0);
            check(m.status == 0xC000000D, "related flag on first request -> INVALID_PARAMETER (0x" + Integer.toHexString(m.status) + ")");

            // Clean up
            c.sendRaw(c.compound(true, c.request(5, 0, createBody(name, 0x00010080, 1, 0x1000)), c.request(6, 0, closeBody(REL))));
            r = c.recv();
            check(r.size() == 2 && r.get(0).status == 0 && r.get(1).status == 0, "delete on close via compound");
        }
    }

    static byte[] smb1Negotiate(String... dialects) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] hdr = new byte[32];
        hdr[0] = (byte) 0xFF; hdr[1] = 'S'; hdr[2] = 'M'; hdr[3] = 'B';
        hdr[4] = 0x72;
        hdr[9] = 0x18;
        hdr[10] = 0x53; hdr[11] = (byte) 0xC8;
        bos.write(hdr, 0, 32);
        bos.write(0);
        ByteArrayOutputStream d = new ByteArrayOutputStream();
        for (String s : dialects) {
            d.write(2);
            byte[] b = s.getBytes(StandardCharsets.US_ASCII);
            d.write(b, 0, b.length);
            d.write(0);
        }
        bos.write(d.size());
        bos.write(d.size() >> 8);
        byte[] db = d.toByteArray();
        bos.write(db, 0, db.length);
        return bos.toByteArray();
    }

    static void testSmb1Negotiate(int port) throws Exception {
        try (Client c = new Client(port)) {
            c.sendRaw(smb1Negotiate("NT LM 0.12", "SMB 2.002", "SMB 2.???"));
            Msg m = c.recv().get(0);
            check(m.raw[0] == (byte) 0xFE && m.status == 0 && m.u16(4) == 0x02FF, "SMB1 multi-protocol negotiate -> SMB2 wildcard (0x"
                    + Integer.toHexString(m.u16(4)) + ")");
            c.msgId = 1;
            c.negotiate(0x0202, 0x0210, 0x0300);
            c.anonymousSession();
            c.treeConnect("\\\\127.0.0.1\\Internal");
            check(c.treeId != 0, "session after multi-protocol negotiate");
        }

        try (Client c = new Client(port)) {
            c.sendRaw(smb1Negotiate("NT LM 0.12", "SMB 2.002"));
            Msg m = c.recv().get(0);
            check(m.raw[0] == (byte) 0xFE && m.status == 0 && m.u16(4) == 0x0202, "SMB1 negotiate offering SMB 2.002 only -> 0x"
                    + Integer.toHexString(m.u16(4)));
            c.msgId = 1;
            c.anonymousSession();
            c.treeConnect("\\\\127.0.0.1\\Internal");
            check(c.treeId != 0, "session after SMB 2.002 negotiate via SMB1");
        }

        try (Client c = new Client(port)) {
            c.sendRaw(smb1Negotiate("NT LM 0.12"));
            byte[] raw = c.recvRaw();
            check(raw[0] == (byte) 0xFF, "SMB1 only negotiate still gets an SMB1 response");
        }
    }

    static void testMisc(int port) throws Exception {
        try (Client c = new Client(port)) {
            c.negotiate(0x0202, 0x0210);

            // Requests without a session
            Msg m = c.call(13, echoBody());
            check(m.status == 0, "echo without a session");
            m = c.call(3, new byte[]{9, 0, 0, 0, 72, 0, 0, 0});
            check(m.status == 0xC0000203, "tree connect without a session -> USER_SESSION_DELETED (0x" + Integer.toHexString(m.status) + ")");

            c.anonymousSession();
            c.treeConnect("\\\\127.0.0.1\\Internal");

            m = c.call(5, createBody("", 0x00100081, 1, 1));
            long fid = m.i64(64 + 8);
            check(m.status == 0, "open share root");

            // Query directory with a buffer that is too small for one entry
            m = c.call(14, queryDirBody(fid, 37, "*", 16));
            check(m.status == 0xC0000004, "query directory tiny buffer -> INFO_LENGTH_MISMATCH (0x" + Integer.toHexString(m.status) + ")");

            // The entry that did not fit is returned next
            m = c.call(14, queryDirBody(fid, 37, "*", 4096));
            check(m.status == 0, "query directory continues after a small buffer");

            // Bad information class
            m = c.call(14, queryDirBody(fid, 99, "*", 4096));
            check(m.status == 0xC0000003, "query directory bad class -> INVALID_INFO_CLASS (0x" + Integer.toHexString(m.status) + ")");

            // File system information
            m = c.call(16, queryInfoBody(fid, 2, 5, 256));
            check(m.status == 0, "filesystem attribute information");
            m = c.call(16, queryInfoBody(fid, 2, 3, 256));
            check(m.status == 0 && m.i64(8) > 0, "filesystem size information");
            m = c.call(16, queryInfoBody(fid, 3, 0, 4));
            check(m.status == 0xC0000023, "security descriptor small buffer -> BUFFER_TOO_SMALL (0x" + Integer.toHexString(m.status) + ")");
            m = c.call(16, queryInfoBody(fid, 3, 0, 1024));
            check(m.status == 0, "security descriptor");

            // File all information with a buffer too small for the name
            m = c.call(16, queryInfoBody(fid, 1, 18, 100));
            check(m.status == 0x80000005 || m.status == 0, "file all information small buffer (0x" + Integer.toHexString(m.status) + ")");

            // Invalid file id
            m = c.call(6, closeBody(0x1234567L));
            check(m.status == 0xC0000128, "close invalid id -> FILE_CLOSED (0x" + Integer.toHexString(m.status) + ")");

            // Unknown command
            m = c.call(0x55, new byte[8]);
            check(m.status == 0xC00000BB, "unknown command -> NOT_SUPPORTED (0x" + Integer.toHexString(m.status) + ")");

            // Tree disconnect then use
            m = c.call(4, new byte[]{4, 0, 0, 0});
            check(m.status == 0, "tree disconnect");
            m = c.call(6, closeBody(fid));
            check(m.status == 0xC00000C9, "request on disconnected tree -> NETWORK_NAME_DELETED (0x" + Integer.toHexString(m.status) + ")");

            // Logoff then use
            m = c.call(2, new byte[]{4, 0, 0, 0});
            check(m.status == 0, "logoff");
            m = c.call(3, new byte[]{9, 0, 0, 0, 72, 0, 0, 0});
            check(m.status == 0xC0000203, "request after logoff -> USER_SESSION_DELETED (0x" + Integer.toHexString(m.status) + ")");
        }

        // Unknown share
        try (Client c = new Client(port)) {
            c.negotiate(0x0210);
            c.anonymousSession();
            boolean failed = false;
            try {
                c.treeConnect("\\\\127.0.0.1\\NoSuchShare");
            }
            catch (IOException ex) {
                failed = ex.getMessage().contains("c00000cc");
            }
            check(failed, "unknown share -> BAD_NETWORK_NAME");
        }
    }

    static void testFuzz(int port, int iterations) throws Exception {
        Random rnd = new Random(12345);
        int closed = 0, answered = 0;

        Client c = null;
        long fid = 0;

        for (int i = 0; i < iterations; i++) {
            try {
                if (c == null) {
                    c = session(port);
                    Msg m = c.call(5, createBody("", 0x00100081, 1, 1));
                    fid = m.i64(64 + 8);
                }

                byte[] msg;
                switch (rnd.nextInt(8)) {
                    case 0: msg = c.request(5, 0, createBody("fuzz" + rnd.nextInt(10), rnd.nextInt(), rnd.nextInt(6), rnd.nextInt())); break;
                    case 1: msg = c.request(14, 0, queryDirBody(fid, rnd.nextInt(40), "*", rnd.nextInt(70000))); break;
                    case 2: msg = c.request(16, 0, queryInfoBody(fid, rnd.nextInt(5), rnd.nextInt(60), rnd.nextInt(70000))); break;
                    case 3: msg = c.request(9, 0, writeBody(fid, rnd.nextLong(), new byte[rnd.nextInt(200)])); break;
                    case 4: msg = c.request(11, 0, new byte[56 + rnd.nextInt(64)]); break;
                    case 5: msg = c.request(17, 0, new byte[32 + rnd.nextInt(64)]); break;
                    case 6: msg = c.request(10, 0, new byte[48 + rnd.nextInt(64)]); break;
                    default: msg = c.request(rnd.nextInt(20), 0, new byte[rnd.nextInt(128)]); break;
                }

                // Mutate
                int mutations = rnd.nextInt(6);
                for (int k = 0; k < mutations; k++) {
                    int pos = 4 + rnd.nextInt(msg.length - 4);
                    msg[pos] = (byte) rnd.nextInt(256);
                }
                if (rnd.nextInt(10) == 0)
                    msg = java.util.Arrays.copyOf(msg, Math.max(1, rnd.nextInt(msg.length + 1)));
                if (rnd.nextInt(10) == 0) {
                    byte[] ext = new byte[msg.length + rnd.nextInt(300)];
                    rnd.nextBytes(ext);
                    System.arraycopy(msg, 0, ext, 0, msg.length);
                    msg = ext;
                }

                c.sendRaw(msg);
                try {
                    c.sock.setSoTimeout(1500);
                    c.recvRaw();
                    answered++;
                }
                catch (SocketTimeoutException ex) {
                    // No response, e.g. a cancel or a request that went async
                    c.close();
                    c = null;
                }
            }
            catch (EOFException ex) {
                closed++;
                if (c != null)
                    c.close();
                c = null;
            }
            catch (IOException ex) {
                closed++;
                if (c != null)
                    c.close();
                c = null;
            }
        }
        if (c != null)
            c.close();

        check(answered > iterations / 2, "most fuzzed requests are answered, " + answered + " of " + iterations + ", " + closed
                + " connections closed");

        // Garbage straight after connecting
        for (int i = 0; i < 50; i++) {
            try (Client g = new Client(port)) {
                byte[] junk = new byte[rnd.nextInt(300) + 1];
                rnd.nextBytes(junk);
                if (rnd.nextBoolean()) {
                    junk[0] = (byte) (rnd.nextBoolean() ? 0xFE : 0xFF);
                    if (junk.length > 3) { junk[1] = 'S'; junk[2] = 'M'; junk[3] = 'B'; }
                }
                g.sendRaw(junk);
                g.sock.setSoTimeout(300);
                try { g.recvRaw(); } catch (IOException ex) { }
            }
        }

        // Huge length prefix
        try (Client g = new Client(port)) {
            g.out.write(new byte[]{0, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 1, 2, 3});
            g.out.flush();
            g.sock.setSoTimeout(500);
            try { g.in.read(); } catch (IOException ex) { }
        }

        // The server must still be working
        try (Client ok = session(port)) {
            Msg m = ok.call(13, echoBody());
            check(m.status == 0, "server responsive after fuzzing");
        }
    }
}
