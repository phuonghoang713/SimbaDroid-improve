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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.FileTime;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileAllInformation;
import com.hierynomus.msfscc.fileinformation.FileBasicInformation;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2Dialect;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.mssmb2.SMBApiException;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Directory;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Parameterized;

/**
 * Runs a set of file operations against the server using the smbj client, for each SMB2/SMB3 dialect and with
 * guest access, authenticated access, signing and encryption.
 */
@RunWith(Parameterized.class)
public class SmbjInteropTest {

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

    @Parameters(name = "{0} {1}")
    public static Collection<Object[]> parameters() {
        List<Object[]> params = new ArrayList<Object[]>();

        for (SMB2Dialect dialect : new SMB2Dialect[]{SMB2Dialect.SMB_2_0_2, SMB2Dialect.SMB_2_1, SMB2Dialect.SMB_3_0,
                SMB2Dialect.SMB_3_0_2, SMB2Dialect.SMB_3_1_1}) {
            params.add(new Object[]{dialect, "guest"});
            params.add(new Object[]{dialect, "anonymous"});
            params.add(new Object[]{dialect, "user"});
            params.add(new Object[]{dialect, "sign"});
            params.add(new Object[]{dialect, "threaded"});
            if (dialect.isSmb3x())
                params.add(new Object[]{dialect, "encrypt"});
        }
        return params;
    }

    private final SMB2Dialect dialect;
    private final String mode;

    public SmbjInteropTest(SMB2Dialect dialect, String mode) {
        this.dialect = dialect;
        this.mode = mode;
    }

    private static void check(boolean cond, String what) {
        assertTrue(what, cond);
    }

    @Test
    public void fileOperations() throws Exception {
        boolean guest = mode.equals("guest") || mode.equals("anonymous");
        TestSmbServer server = guest ? guestServer : mode.equals("threaded") ? threadedServer : userServer;

        SmbConfig config = SmbConfig.builder().withDialects(dialect).withSigningRequired(mode.equals("sign") || mode.equals("threaded"))
                .withEncryptData(mode.equals("encrypt")).withDfsEnabled(false).build();

        try (SMBClient client = new SMBClient(config); Connection conn = client.connect("127.0.0.1", server.getPort())) {
            assertEquals(dialect, conn.getNegotiatedProtocol().getDialect());

            AuthenticationContext ac;
            if (mode.equals("guest"))
                ac = new AuthenticationContext("someone", "whatever".toCharArray(), "");
            else if (mode.equals("anonymous"))
                ac = AuthenticationContext.anonymous();
            else
                ac = new AuthenticationContext(TestSmbServer.USER, TestSmbServer.PASSWORD.toCharArray(), "WORKGROUP");

            Session session = conn.authenticate(ac);
            assertEquals(mode.equals("guest"), session.isGuest());
            assertEquals(mode.equals("anonymous"), session.isAnonymous());

            try (DiskShare share = (DiskShare) session.connectShare(TestSmbServer.SHARE)) {
                runTests(share, dialect.name());
            }
            session.logoff();
        }
    }

    static void runTests(DiskShare share, String tag) throws Exception {
        String dir = "t_" + tag + "_" + System.nanoTime();

        // Directory create
        share.mkdir(dir);
        check(share.folderExists(dir), "mkdir");

        // Small file write/read
        byte[] small = "Hello SMB2 world".getBytes("UTF-8");
        try (File f = share.openFile(dir + "\\small.txt", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_CREATE, null)) {
            f.write(small, 0);
        }
        check(share.fileExists(dir + "\\small.txt"), "create small file");

        try (File f = share.openFile(dir + "\\small.txt", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN, null)) {
            byte[] buf = new byte[100];
            int rd = f.read(buf, 0);
            check(rd == small.length && Arrays.equals(Arrays.copyOf(buf, rd), small), "read small file (" + rd + ")");
        }

        // Large file write/read via streams
        byte[] big = new byte[5 * 1024 * 1024 + 12345];
        new Random(42).nextBytes(big);
        long t0 = System.currentTimeMillis();
        try (File f = share.openFile(dir + "\\big.bin", EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OVERWRITE_IF, null)) {
            try (OutputStream os = f.getOutputStream()) {
                os.write(big);
            }
        }
        long t1 = System.currentTimeMillis();
        byte[] back = new byte[big.length + 10];
        int total = 0;
        try (File f = share.openFile(dir + "\\big.bin", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN, null)) {
            try (InputStream is = f.getInputStream()) {
                int rd;
                while ((rd = is.read(back, total, back.length - total)) > 0)
                    total += rd;
            }
        }
        long t2 = System.currentTimeMillis();
        check(total == big.length && Arrays.equals(Arrays.copyOf(back, total), big),
                "large file round trip (" + total + " bytes, write " + (t1 - t0) + "ms, read " + (t2 - t1) + "ms)");

        // File information
        FileAllInformation info = share.getFileInformation(dir + "\\big.bin");
        check(info.getStandardInformation().getEndOfFile() == big.length, "file size " + info.getStandardInformation().getEndOfFile());
        check(!info.getStandardInformation().isDirectory(), "not a directory");
        FileAllInformation dinfo = share.getFileInformation(dir);
        check(dinfo.getStandardInformation().isDirectory(), "directory info");

        // Set the modification time
        long mtime = 1500000000000L;
        try (File f = share.openFile(dir + "\\small.txt", EnumSet.of(AccessMask.FILE_WRITE_ATTRIBUTES, AccessMask.FILE_READ_ATTRIBUTES),
                null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
            FileBasicInformation bi = new FileBasicInformation(FileBasicInformation.DONT_SET, FileBasicInformation.DONT_SET,
                    FileTime.ofEpochMillis(mtime), FileBasicInformation.DONT_SET, 0);
            f.setFileInformation(bi);
        }
        long got = share.getFileInformation(dir + "\\small.txt").getBasicInformation().getLastWriteTime().toEpochMillis();
        check(got == mtime, "set last write time (" + got + ")");

        // Many files, directory listing across several responses
        int n = 300;
        for (int i = 0; i < n; i++) {
            try (File f = share.openFile(dir + "\\file_with_a_reasonably_long_name_" + i + ".dat",
                    EnumSet.of(AccessMask.GENERIC_WRITE), null, SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_CREATE, null)) {
                // empty
            }
        }
        List<FileIdBothDirectoryInformation> list = share.list(dir);
        int files = 0;
        boolean dot = false, dotdot = false;
        for (FileIdBothDirectoryInformation e : list) {
            if (e.getFileName().equals(".")) dot = true;
            else if (e.getFileName().equals("..")) dotdot = true;
            else files++;
        }
        check(files == n + 2, "list directory, " + files + " entries");
        check(dot && dotdot, "dot entries present");

        List<FileIdBothDirectoryInformation> wild = share.list(dir, "*.txt");
        check(wild.size() == 1 && wild.get(0).getFileName().equals("small.txt"), "wildcard listing (" + wild.size() + ")");

        List<FileIdBothDirectoryInformation> single = share.list(dir, "big.bin");
        check(single.size() == 1 && single.get(0).getEndOfFile() == big.length, "single file listing");

        // Rename
        try (File f = share.openFile(dir + "\\small.txt", EnumSet.of(AccessMask.DELETE, AccessMask.GENERIC_READ), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
            f.rename(dir + "\\renamed.txt");
        }
        check(share.fileExists(dir + "\\renamed.txt") && !share.fileExists(dir + "\\small.txt"), "rename file");

        // Rename over an existing file without and with replace
        boolean collision = false;
        try (File f = share.openFile(dir + "\\renamed.txt", EnumSet.of(AccessMask.DELETE, AccessMask.GENERIC_READ), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
            f.rename(dir + "\\big.bin", false);
        }
        catch (SMBApiException ex) {
            collision = ex.getStatusCode() == 0xC0000035L;
        }
        check(collision, "rename without replace fails with name collision");

        try (File f = share.openFile(dir + "\\renamed.txt", EnumSet.of(AccessMask.DELETE, AccessMask.GENERIC_READ), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
            f.rename(dir + "\\big.bin", true);
        }
        check(share.getFileInformation(dir + "\\big.bin").getStandardInformation().getEndOfFile() == small.length, "rename with replace");

        // Sub directory and rename of directory
        share.mkdir(dir + "\\sub");
        try (Directory d = share.openDirectory(dir + "\\sub", EnumSet.of(AccessMask.DELETE, AccessMask.GENERIC_READ), null,
                SMB2ShareAccess.ALL, SMB2CreateDisposition.FILE_OPEN, null)) {
            d.rename(dir + "\\sub2");
        }
        check(share.folderExists(dir + "\\sub2") && !share.folderExists(dir + "\\sub"), "rename directory");

        // Open of a missing file / missing path
        long sts = 0;
        try {
            share.openFile(dir + "\\nosuchfile", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN, null).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000034L, "open missing file -> OBJECT_NAME_NOT_FOUND (0x" + Long.toHexString(sts) + ")");

        sts = 0;
        try {
            share.openFile(dir + "\\nodir\\nosuchfile", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN, null).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC000003AL, "open missing path -> OBJECT_PATH_NOT_FOUND (0x" + Long.toHexString(sts) + ")");

        // Path traversal must be rejected
        sts = 0;
        try {
            share.openFile(dir + "\\..\\..\\..\\etc\\passwd", EnumSet.of(AccessMask.GENERIC_READ), null, SMB2ShareAccess.ALL,
                    SMB2CreateDisposition.FILE_OPEN, null).close();
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000033L, "path traversal rejected (0x" + Long.toHexString(sts) + ")");

        // Removing a non-empty directory fails
        sts = 0;
        try {
            share.rmdir(dir, false);
        }
        catch (SMBApiException ex) {
            sts = ex.getStatusCode();
        }
        check(sts == 0xC0000101L, "rmdir non-empty -> DIRECTORY_NOT_EMPTY (0x" + Long.toHexString(sts) + ")");

        // Disk space
        long free = share.getShareInformation().getFreeSpace();
        long totalSpace = share.getShareInformation().getTotalSpace();
        check(totalSpace > 0 && free >= 0 && free <= totalSpace, "share space total=" + totalSpace + " free=" + free);

        // Clean up, recursive delete
        share.rmdir(dir, true);
        check(!share.folderExists(dir), "recursive delete");
    }
}
