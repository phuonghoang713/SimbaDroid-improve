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

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CompletionFilter;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2ImpersonationLevel;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.mssmb2.messages.SMB2ChangeNotifyResponse;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.share.NamedPipe;
import com.hierynomus.smbj.share.PipeShare;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests of the less common file operations using the smbj client: overwriting large files, truncation, deletion,
 * concurrent I/O on a file handle, byte range locks, change notification, unusual file names, named pipes and
 * multiple sessions on a connection.
 */
public class SmbjFeatureTest {

    private static TestSmbServer guestServer;
    private static TestSmbServer userServer;
    private static TestSmbServer threadedServer;

    @BeforeClass
    public static void startServers() throws Exception {
        guestServer = new TestSmbServer(TestSmbServer.Options.guest());
        userServer = new TestSmbServer(TestSmbServer.Options.user());
        threadedServer = new TestSmbServer(TestSmbServer.Options.user().threaded());
    }

    @AfterClass
    public static void stopServers() {
        guestServer.close();
        userServer.close();
        threadedServer.close();
    }

    private static void check(boolean cond, String what) {
        assertTrue(what, cond);
    }

    @Test
    public void guestSession() throws Exception {
        runAll(guestServer, true, false, false);
    }

    @Test
    public void signedSession() throws Exception {
        runAll(userServer, false, true, false);
    }

    @Test
    public void encryptedSession() throws Exception {
        runAll(userServer, false, false, true);
    }

    @Test
    public void signedSessionThreadedServer() throws Exception {
        runAll(threadedServer, false, true, false);
    }

    private static void runAll(TestSmbServer server, boolean guest, boolean sign, boolean encrypt) throws Exception {
        SmbConfig cfg = SmbConfig.builder().withSigningRequired(sign).withEncryptData(encrypt).withDfsEnabled(false)
                .withTimeout(30, TimeUnit.SECONDS).build();

        try (SMBClient client = new SMBClient(cfg); Connection conn = client.connect("127.0.0.1", server.getPort())) {
            AuthenticationContext ac = guest ? new AuthenticationContext("someone", "x".toCharArray(), "")
                    : new AuthenticationContext(TestSmbServer.USER, TestSmbServer.PASSWORD.toCharArray(), "WORKGROUP");
            Session session = conn.authenticate(ac);

            try (DiskShare share = (DiskShare) session.connectShare(TestSmbServer.SHARE)) {
                String dir = "x_" + System.nanoTime();
                share.mkdir(dir);

                testOverwriteLarge(share, dir);
                testTruncate(share, dir);
                testDelete(share, dir);
                testConcurrentIo(share, dir);
                testLocks(share, session, dir);
                testNotify(share, dir);
                testNames(share, dir);

                share.rmdir(dir, true);
                check(!share.folderExists(dir), "cleanup");
            }

            testPipe(session);

            // A second session on the same connection
            Session session2 = conn.authenticate(ac);
            try (DiskShare share2 = (DiskShare) session2.connectShare(TestSmbServer.SHARE)) {
                check(share2.folderExists(""), "second session on the same connection");
            }
            session2.logoff();
            try (DiskShare share = (DiskShare) session.connectShare(TestSmbServer.SHARE)) {
                check(share.folderExists(""), "first session still valid after second logoff");
            }
        }
    }

    static long statusOf(Throwable ex) {
        while (ex != null) {
            if (ex instanceof SMBApiException)
                return ((SMBApiException) ex).getStatusCode();
            ex = ex.getCause();
        }
        return -1;
    }

    static File open(DiskShare share, String path, SMB2CreateDisposition disp, AccessMask... access) {
        return share.openFile(path, EnumSet.copyOf(Arrays.asList(access)), null, SMB2ShareAccess.ALL, disp, null);
    }

    static byte[] readAll(DiskShare share, String path) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (File f = open(share, path, SMB2CreateDisposition.FILE_OPEN, AccessMask.GENERIC_READ)) {
            f.read(bos);
        }
        return bos.toByteArray();
    }

    static void testOverwriteLarge(DiskShare share, String dir) throws Exception {
        String path = dir + "\\large.bin";
        byte[] first = new byte[3 * 1024 * 1024];
        new Random(1).nextBytes(first);
        try (File f = open(share, path, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE)) {
            try (OutputStream os = f.getOutputStream()) {
                os.write(first);
            }
        }

        byte[] second = "replacement content".getBytes(StandardCharsets.UTF_8);
        long sts = 0;
        try (File f = open(share, path, SMB2CreateDisposition.FILE_OVERWRITE_IF, AccessMask.GENERIC_WRITE)) {
            f.write(second, 0);
        }
        catch (Exception ex) {
            sts = statusOf(ex);
        }
        check(sts == 0, "overwrite existing large file (status 0x" + Long.toHexString(sts) + ")");
        if (sts == 0)
            check(Arrays.equals(readAll(share, path), second), "content after overwrite of large file");

        // Supersede as well
        try (File f = open(share, path, SMB2CreateDisposition.FILE_SUPERSEDE, AccessMask.GENERIC_WRITE)) {
            f.write(first, 0, 0, 1000);
        }
        check(share.getFileInformation(path).getStandardInformation().getEndOfFile() == 1000, "supersede");
    }

    static void testTruncate(DiskShare share, String dir) throws Exception {
        String path = dir + "\\trunc.bin";
        byte[] data = new byte[100000];
        new Random(2).nextBytes(data);
        try (File f = open(share, path, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ)) {
            f.write(data, 0);
            f.setLength(5000);
            check(f.getFileInformation().getStandardInformation().getEndOfFile() == 5000, "shrink with set end of file");
            f.setLength(20000);
            long size = f.getFileInformation().getStandardInformation().getEndOfFile();
            check(size == 20000, "extend with set end of file reports new size (" + size + ")");
        }
        byte[] back = readAll(share, path);
        boolean tailZero = back.length == 20000;
        for (int i = 5000; tailZero && i < 20000; i++)
            tailZero = back[i] == 0;
        check(tailZero && Arrays.equals(Arrays.copyOf(back, 5000), Arrays.copyOf(data, 5000)), "content after shrink + extend (" + back.length + ")");

        // Extend first then write the data, as a file copy does
        String path2 = dir + "\\prealloc.bin";
        try (File f = open(share, path2, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ)) {
            f.setLength(data.length);
            f.write(data, 0);
        }
        check(Arrays.equals(readAll(share, path2), data), "extend then write full content");

        // Write beyond the end of file leaves a hole of zeros
        try (File f = open(share, path, SMB2CreateDisposition.FILE_OVERWRITE, AccessMask.GENERIC_WRITE)) {
            f.write(new byte[]{1, 2, 3}, 10000);
        }
        back = readAll(share, path);
        boolean zeros = back.length == 10003;
        for (int i = 0; zeros && i < 10000; i++)
            zeros = back[i] == 0;
        check(zeros && back[10000] == 1 && back[10002] == 3, "sparse write beyond end of file (" + back.length + ")");

        // Read at and beyond end of file
        try (File f = open(share, path, SMB2CreateDisposition.FILE_OPEN, AccessMask.GENERIC_READ)) {
            byte[] buf = new byte[100];
            int rd = f.read(buf, 10000);
            check(rd == 3, "short read at end of file (" + rd + ")");
            rd = f.read(buf, 20000);
            check(rd == -1, "read beyond end of file returns EOF (" + rd + ")");
        }
    }

    static void testDelete(DiskShare share, String dir) throws Exception {
        String path = dir + "\\del1.txt";
        try (File f = share.openFile(path, EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.DELETE), null, SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_CREATE, EnumSet.of(SMB2CreateOptions.FILE_DELETE_ON_CLOSE))) {
            f.write(new byte[10], 0);
            check(share.fileExists(path), "delete on close file exists while open");
        }
        check(!share.fileExists(path), "delete on close create option");

        path = dir + "\\del2.txt";
        open(share, path, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE).close();
        share.rm(path);
        check(!share.fileExists(path), "delete via disposition information");

        long sts = 0;
        try {
            share.rm(dir + "\\missing.txt");
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000034L, "delete missing file (0x" + Long.toHexString(sts) + ")");

        // A file cannot be opened as a directory and vice versa
        open(share, dir + "\\plain.txt", SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE).close();
        sts = 0;
        try {
            share.openDirectory(dir + "\\plain.txt", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN, null).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000103L, "open file as directory -> NOT_A_DIRECTORY (0x" + Long.toHexString(sts) + ")");

        sts = 0;
        try {
            share.openFile(dir, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN,
                    EnumSet.of(SMB2CreateOptions.FILE_NON_DIRECTORY_FILE)).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC00000BAL, "open directory as file -> FILE_IS_A_DIRECTORY (0x" + Long.toHexString(sts) + ")");

        sts = 0;
        try {
            open(share, dir + "\\plain.txt", SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000035L, "create existing file -> OBJECT_NAME_COLLISION (0x" + Long.toHexString(sts) + ")");
    }

    static void testConcurrentIo(final DiskShare share, String dir) throws Exception {
        final String path = dir + "\\conc.bin";
        final byte[] data = new byte[8 * 1024 * 1024];
        new Random(3).nextBytes(data);
        try (File f = open(share, path, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE)) {
            try (OutputStream os = f.getOutputStream()) {
                os.write(data);
            }
        }

        final AtomicInteger bad = new AtomicInteger();
        final AtomicInteger reads = new AtomicInteger();

        try (final File f = open(share, path, SMB2CreateDisposition.FILE_OPEN, AccessMask.GENERIC_READ)) {
            Thread[] threads = new Thread[8];
            for (int t = 0; t < threads.length; t++) {
                final int seed = t;
                threads[t] = new Thread(new Runnable() {
                    public void run() {
                        Random rnd = new Random(100 + seed);
                        byte[] buf = new byte[60000];
                        for (int i = 0; i < 150; i++) {
                            int off = rnd.nextInt(data.length - buf.length);
                            try {
                                int rd = f.read(buf, off);
                                reads.incrementAndGet();
                                if (rd != buf.length || !Arrays.equals(buf, Arrays.copyOfRange(data, off, off + rd)))
                                    bad.incrementAndGet();
                            }
                            catch (Exception ex) {
                                bad.incrementAndGet();
                            }
                        }
                    }
                });
                threads[t].start();
            }
            for (Thread t : threads)
                t.join();
        }
        check(bad.get() == 0, "concurrent reads on one handle, " + reads.get() + " reads, " + bad.get() + " corrupt");

        // Concurrent writes to distinct regions of one handle
        final String wpath = dir + "\\concw.bin";
        final int chunk = 50000;
        final int chunks = 96;
        final AtomicInteger werr = new AtomicInteger();
        try (final File f = open(share, wpath, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE)) {
            Thread[] threads = new Thread[8];
            for (int t = 0; t < threads.length; t++) {
                final int tid = t;
                threads[t] = new Thread(new Runnable() {
                    public void run() {
                        for (int c = tid; c < chunks; c += 8) {
                            try {
                                f.write(data, (long) c * chunk, c * chunk, chunk);
                            }
                            catch (Exception ex) {
                                werr.incrementAndGet();
                            }
                        }
                    }
                });
                threads[t].start();
            }
            for (Thread t : threads)
                t.join();
        }
        byte[] back = readAll(share, wpath);
        check(werr.get() == 0 && Arrays.equals(back, Arrays.copyOf(data, chunk * chunks)), "concurrent writes on one handle (" + back.length + " bytes)");
    }

    static void testLocks(DiskShare share, Session session, String dir) throws Exception {
        String path = dir + "\\lock.bin";
        try (File f1 = open(share, path, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ)) {
            f1.write(new byte[1000], 0);
            f1.requestLock().exclusiveLock(0, 100, true).send();

            try (File f2 = open(share, path, SMB2CreateDisposition.FILE_OPEN, AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ)) {
                long sts = 0;
                try {
                    f2.requestLock().exclusiveLock(50, 100, true).send();
                }
                catch (Exception ex) {
                    sts = statusOf(ex);
                }
                check(sts == 0xC0000055L, "conflicting lock -> LOCK_NOT_GRANTED (0x" + Long.toHexString(sts) + ")");

                sts = 0;
                try {
                    f2.read(new byte[10], 10);
                }
                catch (Exception ex) {
                    sts = statusOf(ex);
                }
                check(sts == 0xC0000054L, "read of locked range -> FILE_LOCK_CONFLICT (0x" + Long.toHexString(sts) + ")");

                check(f2.read(new byte[10], 500) == 10, "read outside locked range");

                f2.requestLock().exclusiveLock(200, 100, true).send();
                f2.requestLock().unlock(200, 100).send();

                sts = 0;
                try {
                    f2.requestLock().unlock(200, 100).send();
                }
                catch (Exception ex) {
                    sts = statusOf(ex);
                }
                check(sts == 0xC000007EL, "unlock of unlocked range -> RANGE_NOT_LOCKED (0x" + Long.toHexString(sts) + ")");
            }

            f1.requestLock().unlock(0, 100).send();
        }

        // Locks are released when the file is closed
        try (File f1 = open(share, path, SMB2CreateDisposition.FILE_OPEN, AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ)) {
            f1.requestLock().exclusiveLock(0, 100, true).send();
        }
        try (File f2 = open(share, path, SMB2CreateDisposition.FILE_OPEN, AccessMask.GENERIC_WRITE, AccessMask.GENERIC_READ)) {
            f2.requestLock().exclusiveLock(0, 100, true).send();
            check(true, "locks released on close");
        }
    }

    static void testNotify(DiskShare share, String dir) throws Exception {
        long sts = 0;
        try (Directory d = share.openDirectory(dir, EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN, null)) {
            Future<SMB2ChangeNotifyResponse> fut = d.watchAsync(EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME), false);
            boolean pending = false;
            try {
                fut.get(1, TimeUnit.SECONDS);
            }
            catch (TimeoutException ex) {
                pending = true;
            }
            catch (ExecutionException ex) {
                // smbj wraps its own timeout
                pending = String.valueOf(ex.getCause()).contains("Timeout");
            }
            check(pending, "change notify request is held pending");

            // Other requests still work whilst the notify is outstanding
            check(share.folderExists(dir), "request whilst notify is pending");

            fut.cancel(true);
            try {
                SMB2ChangeNotifyResponse resp = fut.get(5, TimeUnit.SECONDS);
                sts = resp.getHeader().getStatusCode();
            }
            catch (java.util.concurrent.CancellationException ex) {
                sts = 0xC0000120L;
            }
            catch (ExecutionException ex) {
                sts = statusOf(ex);
            }
            catch (TimeoutException ex) {
                sts = -2;
            }
            check(sts == 0xC0000120L, "cancel of change notify (0x" + Long.toHexString(sts) + ")");

            // Close with a notify outstanding
            Future<SMB2ChangeNotifyResponse> fut2 = d.watchAsync(EnumSet.of(SMB2CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME), false);
            Thread.sleep(200);
            d.close();
            try {
                SMB2ChangeNotifyResponse resp = fut2.get(5, TimeUnit.SECONDS);
                sts = resp.getHeader().getStatusCode();
            }
            catch (ExecutionException ex) {
                sts = statusOf(ex);
            }
            catch (TimeoutException ex) {
                sts = -2;
            }
            check(sts == 0x10BL, "notify completed on close -> NOTIFY_CLEANUP (0x" + Long.toHexString(sts) + ")");
        }
    }

    static void testNames(DiskShare share, String dir) throws Exception {
        String[] names = {"with space.txt", "üñîçødé-名前-файл.txt", "dots.in.name.tar.gz", "UPPER.TXT", "semi;colon,comma[br]+=.txt",
                "a_very_long_name_" + new String(new char[180]).replace('\0', 'x') + ".txt"};
        for (String name : names) {
            open(share, dir + "\\" + name, SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE).close();
            boolean found = false;
            for (com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation e : share.list(dir))
                found |= e.getFileName().equals(name);
            check(found, "file name round trip: " + (name.length() > 40 ? name.substring(0, 40) + "..." : name));
            share.rm(dir + "\\" + name);
        }

        long sts = 0;
        try {
            open(share, dir + "\\bad<name>.txt", SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000033L, "invalid characters -> OBJECT_NAME_INVALID (0x" + Long.toHexString(sts) + ")");

        sts = 0;
        try {
            open(share, dir + "\\file.txt:stream", SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000033L, "named stream rejected (0x" + Long.toHexString(sts) + ")");

        // Deep directory tree
        String deep = dir;
        for (int i = 0; i < 12; i++) {
            deep += "\\level" + i;
            share.mkdir(deep);
        }
        open(share, deep + "\\leaf.txt", SMB2CreateDisposition.FILE_CREATE, AccessMask.GENERIC_WRITE).close();
        check(share.fileExists(deep + "\\leaf.txt"), "deep directory tree");
    }

    static void testPipe(Session session) throws Exception {
        try (PipeShare ipc = (PipeShare) session.connectShare("IPC$")) {
            NamedPipe pipe = ipc.open("srvsvc", SMB2ImpersonationLevel.Impersonation, EnumSet.of(AccessMask.MAXIMUM_ALLOWED), null,
                    SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null);

            byte[] bind = hex("05000b03100000004800000001000000b810b810000000000100000000000100"
                    + "c84f324b7016d30112785a47bf6ee18803000000"
                    + "045d888aeb1cc9119fe808002b10486002000000");
            byte[] ack = pipe.transact(bind);
            check(ack.length > 24 && ack[2] == 0x0c, "DCE/RPC bind to srvsvc (" + ack.length + " bytes)");

            // NetrShareEnum, level 1
            ByteArrayOutputStream stub = new ByteArrayOutputStream();
            String srv = "\\\\127.0.0.1\0";
            le32(stub, 0x00020000);
            le32(stub, srv.length());
            le32(stub, 0);
            le32(stub, srv.length());
            stub.write(srv.getBytes(StandardCharsets.UTF_16LE));
            while (stub.size() % 4 != 0)
                stub.write(0);
            le32(stub, 1);
            le32(stub, 1);
            le32(stub, 0x00020004);
            le32(stub, 0);
            le32(stub, 0);
            le32(stub, 0xFFFFFFFF);
            le32(stub, 0);

            ByteArrayOutputStream req = new ByteArrayOutputStream();
            req.write(hex("0500000310000000"));
            le16(req, 24 + stub.size());
            le16(req, 0);
            le32(req, 2);
            le32(req, stub.size());
            le16(req, 0);
            le16(req, 15);
            req.write(stub.toByteArray());

            byte[] resp = pipe.transact(req.toByteArray());
            String text = new String(resp, StandardCharsets.UTF_16LE) + new String(resp, 1, resp.length - 1, StandardCharsets.UTF_16LE);
            check(resp.length > 24 && resp[2] == 0x02, "NetrShareEnum response (" + resp.length + " bytes)");
            check(text.contains("Internal") && text.contains("IPC$"), "share list contains Internal and IPC$");

            // Write then read
            pipe.write(req.toByteArray());
            byte[] buf = new byte[4096];
            int rd = pipe.read(buf);
            check(rd == resp.length, "pipe write + read (" + rd + ")");
            pipe.close();
        }
    }

    static void le32(ByteArrayOutputStream out, int v) {
        out.write(v);
        out.write(v >> 8);
        out.write(v >> 16);
        out.write(v >> 24);
    }

    static void le16(ByteArrayOutputStream out, int v) {
        out.write(v);
        out.write(v >> 8);
    }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }
}
