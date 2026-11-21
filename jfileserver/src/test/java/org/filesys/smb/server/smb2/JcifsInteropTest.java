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

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import jcifs.CIFSContext;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbFile;

/**
 * Runs a set of file operations against the server using the jcifs-ng client, which is the SMB client library used
 * by many Android file managers. This also covers the SMB1 protocol, to check that it still works alongside
 * SMB2/SMB3.
 */
public class JcifsInteropTest {

    private static TestSmbServer guestServer;
    private static TestSmbServer userServer;

    @BeforeClass
    public static void startServers() throws Exception {
        guestServer = new TestSmbServer(TestSmbServer.Options.guest());
        userServer = new TestSmbServer(TestSmbServer.Options.user());
    }

    @AfterClass
    public static void stopServers() {
        guestServer.close();
        userServer.close();
    }

    // Protocol version being tested, used to label failures
    private static String currentVersion = "";

    private static void check(boolean cond, String what) {
        assertTrue(currentVersion + ": " + what, cond);
    }

    private static final String[] SMB2_VERSIONS = {"SMB202", "SMB210", "SMB300", "SMB302", "SMB311"};

    @Test
    public void smb1Guest() throws Exception {
        run(guestServer, "SMB1", "guest", false, true);
    }

    @Test
    public void smb1User() throws Exception {
        run(userServer, "SMB1", "user", false, true);
    }

    @Test
    public void smb2Guest() throws Exception {
        for (String ver : SMB2_VERSIONS)
            run(guestServer, ver, "guest", false, false);
    }

    @Test
    public void smb2GuestFallback() throws Exception {
        for (String ver : SMB2_VERSIONS)
            run(guestServer, ver, "fallback", false, false);
    }

    @Test
    public void smb2User() throws Exception {
        for (String ver : SMB2_VERSIONS)
            run(userServer, ver, "user", false, false);
    }

    @Test
    public void smb2UserSigningEnforced() throws Exception {
        for (String ver : SMB2_VERSIONS)
            run(userServer, ver, "user", true, false);
    }

    /**
     * Run the test scenario
     *
     * @param server     TestSmbServer
     * @param ver        String Protocol version to use
     * @param authMode   String
     * @param sign       boolean Enforce signing in the client
     * @param listShares boolean Check the share enumeration. jcifs-ng can only enumerate shares via SMB2 on the
     *                   standard SMB port, as it connects to port 445 to open the server service pipe.
     * @exception Exception Test failed
     */
    private static void run(TestSmbServer server, String ver, String authMode, boolean sign, boolean listShares)
            throws Exception {

        String port = Integer.toString(server.getPort());

        Properties p = new Properties();
        p.setProperty("jcifs.smb.client.minVersion", ver);
        p.setProperty("jcifs.smb.client.maxVersion", ver);
        p.setProperty("jcifs.resolveOrder", "DNS");
        p.setProperty("jcifs.smb.client.responseTimeout", "30000");
        if (authMode.equals("fallback"))
            p.setProperty("jcifs.smb.client.allowGuestFallback", "true");
        if (ver.equals("SMB1")) {
            // The SMB1 server does not use extended security
            p.setProperty("jcifs.smb.lmCompatibility", "2");
            p.setProperty("jcifs.smb.client.useExtendedSecurity", "false");
        }
        if (sign)
            p.setProperty("jcifs.smb.client.signingEnforced", "true");

        CIFSContext base = new BaseContext(new PropertyConfiguration(p));
        CIFSContext ctx;
        if (authMode.equals("guest"))
            ctx = base.withGuestCrendentials();
        else if (authMode.equals("fallback"))
            ctx = base.withCredentials(new NtlmPasswordAuthenticator("", "someone", "whatever"));
        else
            ctx = base.withCredentials(new NtlmPasswordAuthenticator("WORKGROUP", TestSmbServer.USER, TestSmbServer.PASSWORD));

        try {
            scenario(ctx, port, ver, listShares);
        }
        finally {
            ctx.close();
        }
    }

    private static void scenario(CIFSContext ctx, String port, String ver, boolean listShares) throws Exception {
        currentVersion = ver;

        String root = "smb://127.0.0.1:" + port + "/";

        {
            // Share enumeration via the IPC$ pipe
            if (listShares) {
                try (SmbFile server = new SmbFile(root, ctx)) {
                    String[] shares = server.list();
                    check(Arrays.asList(shares).contains("Internal") || Arrays.asList(shares).contains("Internal/"),
                            "share enumeration " + Arrays.toString(shares));
                }
            }

            String dirUrl = root + "Internal/j_" + ver + "_" + System.nanoTime() + "/";
            try (SmbFile dir = new SmbFile(dirUrl, ctx)) {
                dir.mkdir();
                check(dir.exists() && dir.isDirectory(), "mkdir");

                byte[] data = new byte[3 * 1024 * 1024 + 777];
                new Random(7).nextBytes(data);

                try (SmbFile f = new SmbFile(dirUrl + "data.bin", ctx)) {
                    try (OutputStream os = f.getOutputStream()) {
                        os.write(data);
                    }
                    check(f.length() == data.length, "file length " + f.length());

                    byte[] back = new byte[data.length + 10];
                    int total = 0;
                    try (InputStream is = f.getInputStream()) {
                        int rd;
                        while ((rd = is.read(back, total, back.length - total)) > 0)
                            total += rd;
                    }
                    check(total == data.length && Arrays.equals(Arrays.copyOf(back, total), data), "read back " + total + " bytes");

                    long mtime = 1400000000000L;
                    f.setLastModified(mtime);
                    check(f.lastModified() == mtime, "set last modified (" + f.lastModified() + ")");

                    try (SmbFile renamed = new SmbFile(dirUrl + "renamed.bin", ctx)) {
                        f.renameTo(renamed);
                        check(renamed.exists() && renamed.length() == data.length, "rename");
                        check(renamed.lastModified() == mtime, "modification time kept after rename (" + renamed.lastModified() + ")");
                    }
                }

                for (int i = 0; i < 120; i++) {
                    try (SmbFile f = new SmbFile(dirUrl + "entry_number_" + i + ".txt", ctx)) {
                        f.createNewFile();
                    }
                }
                check(dir.list().length == 121, "list " + dir.list().length + " entries");
                check(dir.listFiles("*.bin").length == 1, "wildcard list");

                try (SmbFile sub = new SmbFile(dirUrl + "sub dir/", ctx)) {
                    sub.mkdirs();
                    check(sub.isDirectory(), "sub directory");
                }

                try (SmbFile missing = new SmbFile(dirUrl + "missing.txt", ctx)) {
                    check(!missing.exists(), "missing file does not exist");
                }

                check(dir.getDiskFreeSpace() > 0, "free space " + dir.getDiskFreeSpace());

                dir.delete();
                check(!dir.exists(), "recursive delete");
            }
        }
    }
}
