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

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.stream.Stream;

import org.filesys.debug.DebugConfigSection;
import org.filesys.server.SrvSession;
import org.filesys.server.auth.ClientInfo;
import org.filesys.server.auth.ISMBAuthenticator;
import org.filesys.server.auth.LocalAuthenticator;
import org.filesys.server.auth.SMBAuthenticator;
import org.filesys.server.auth.UserAccount;
import org.filesys.server.auth.UserAccountList;
import org.filesys.server.auth.acl.DefaultAccessControlManager;
import org.filesys.server.config.CoreServerConfigSection;
import org.filesys.server.config.GlobalConfigSection;
import org.filesys.server.config.SecurityConfigSection;
import org.filesys.server.config.ServerConfiguration;
import org.filesys.server.filesys.DiskDeviceContext;
import org.filesys.server.filesys.DiskInterface;
import org.filesys.server.filesys.DiskSharedDevice;
import org.filesys.server.filesys.DiskSizeInterface;
import org.filesys.server.filesys.FilesystemsConfigSection;
import org.filesys.server.filesys.SrvDiskInfo;
import org.filesys.smb.Dialect;
import org.filesys.smb.DialectSelector;
import org.filesys.smb.server.SMBConfigSection;
import org.filesys.smb.server.SMBServer;
import org.filesys.smb.server.SMBSrvSession;
import org.filesys.smb.server.disk.JavaNIODiskDriver;
import org.springframework.extensions.config.element.GenericConfigElement;

/**
 * An SMB server running in the test JVM, sharing a temporary directory as the share "Internal" on a free local port.
 *
 * <p>The configuration mirrors the one that the SimbaDroid app builds, without the Android specific parts.
 */
public final class TestSmbServer implements AutoCloseable {

    public static final String SHARE = "Internal";
    public static final String USER = "test";
    public static final String PASSWORD = "Passw0rd!";

    /** Files of this size or larger are truncated/deleted via the trashcan folder */
    public static final int LARGE_FILE_SIZE = 2 * 1024 * 1024;

    /**
     * Server configuration options
     */
    public static final class Options {
        boolean guest = true;
        boolean requireSigning;
        boolean requireEncryption;
        boolean threaded;
        int maxDialect = Dialect.UpToSMBv3;

        public static Options guest() {
            return new Options();
        }

        public static Options user() {
            Options opts = new Options();
            opts.guest = false;
            return opts;
        }

        public Options requireSigning() {
            requireSigning = true;
            return this;
        }

        public Options requireEncryption() {
            requireEncryption = true;
            return this;
        }

        public Options threaded() {
            threaded = true;
            return this;
        }

        public Options maxDialect(int dialect) {
            maxDialect = dialect;
            return this;
        }
    }

    /**
     * Disk driver that reports the size of the underlying filesystem
     */
    private static final class SizedDiskDriver extends JavaNIODiskDriver implements DiskSizeInterface {
        @Override
        public void getDiskInformation(DiskDeviceContext ctx, SrvDiskInfo info) {
            File root = new File(ctx.getDeviceName());
            info.setBlockSize(512);
            info.setBlocksPerAllocationUnit(8);
            info.setTotalUnits(root.getTotalSpace() / 4096);
            info.setFreeUnits(root.getUsableSpace() / 4096);
        }
    }

    private final File m_root;
    private final int m_port;
    private final ServerConfiguration m_config;
    private SMBServer m_server;

    public TestSmbServer(Options opts)
            throws Exception {

        m_root = Files.createTempDirectory("smbtest").toFile();
        File shareDir = new File(m_root, "share");
        File trashDir = new File(m_root, "trash");
        shareDir.mkdirs();
        trashDir.mkdirs();

        m_port = findFreePort();

        ServerConfiguration cfg = new ServerConfiguration("TESTSRV");
        m_config = cfg;

        DebugConfigSection debugConfig = new DebugConfigSection(cfg);
        debugConfig.setDebug("org.filesys.debug.ConsoleDebug", new GenericConfigElement("output"));

        CoreServerConfigSection coreConfig = new CoreServerConfigSection(cfg);
        coreConfig.setMemoryPool(new int[]{256, 4096, 16384, 66000, 1049600}, new int[]{20, 20, 5, 5, 0},
                new int[]{100, 50, 50, 50, 16});
        coreConfig.setThreadPool(6, 6);
        coreConfig.getThreadPool().setDebug(false);

        new GlobalConfigSection(cfg);

        SecurityConfigSection secConfig = new SecurityConfigSection(cfg);
        DefaultAccessControlManager aclMgr = new DefaultAccessControlManager();
        aclMgr.setDebug(false);
        aclMgr.initialize(cfg, new GenericConfigElement("aclManager"));
        secConfig.setAccessControlManager(aclMgr);

        UserAccountList users = new UserAccountList();
        if (!opts.guest)
            users.addUser(new UserAccount(USER, PASSWORD));
        secConfig.setUserAccounts(users);

        FilesystemsConfigSection fsConfig = new FilesystemsConfigSection(cfg);
        DiskInterface disk = new SizedDiskDriver();

        GenericConfigElement driverConfig = new GenericConfigElement("driver");
        addChild(driverConfig, "LocalPath", shareDir.getAbsolutePath());
        addChild(driverConfig, "TrashcanPath", trashDir.getAbsolutePath());
        addChild(driverConfig, "LargeFileSize", "2M");

        DiskDeviceContext ctx = (DiskDeviceContext) disk.createContext(SHARE, driverConfig);
        ctx.setShareName(SHARE);
        ctx.setConfigurationParameters(driverConfig);
        ctx.enableChangeHandler(false);

        DiskSharedDevice share = new DiskSharedDevice(SHARE, disk, ctx);
        share.setConfiguration(cfg);
        share.setAccessControlList(secConfig.getGlobalAccessControls());
        ctx.startFilesystem(share);
        fsConfig.addShare(share);

        SMBConfigSection smbConfig = new SMBConfigSection(cfg);
        smbConfig.setServerName("TESTSRV");
        smbConfig.setDomainName("WORKGROUP");
        smbConfig.setHostAnnouncer(false);
        smbConfig.setNetBIOSSMB(false);
        smbConfig.setTcpipSMB(true);
        smbConfig.setTcpipSMBPort(m_port);
        smbConfig.setSMBBindAddress(InetAddress.getByName("127.0.0.1"));
        smbConfig.setDisableNIOCode(opts.threaded);

        SMBAuthenticator auth;
        if (opts.guest) {
            // The same authenticator setup as the app uses when no credentials are configured
            auth = new LocalAuthenticator() {
                @Override
                public AuthStatus authenticateUser(ClientInfo client, SrvSession sess, PasswordAlgorithm alg) {
                    return AuthStatus.AUTHENTICATED;
                }
            };
            auth.setAllowGuest(true);
        }
        else {
            auth = new LocalAuthenticator();
            auth.setAllowGuest(false);
        }
        auth.setDebug(false);
        auth.setAccessMode(ISMBAuthenticator.AuthMode.USER);
        auth.initialize(cfg, new GenericConfigElement("authenticator"));
        smbConfig.setAuthenticator(auth);

        DialectSelector dialects = new DialectSelector();
        dialects.enableUpTo(opts.maxDialect);
        smbConfig.setEnabledDialects(dialects);

        smbConfig.setSMB2SigningRequired(opts.requireSigning);
        smbConfig.setSMB3EncryptionRequired(opts.requireEncryption);
        smbConfig.setSessionDebugFlags(EnumSet.noneOf(SMBSrvSession.Dbg.class));

        start();
    }

    private static void addChild(GenericConfigElement parent, String name, String value) {
        GenericConfigElement child = new GenericConfigElement(name);
        child.setValue(value);
        parent.addChild(child);
    }

    private static int findFreePort()
            throws IOException {
        try (ServerSocket sock = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return sock.getLocalPort();
        }
    }

    /**
     * Start the server and wait until it is accepting connections
     *
     * @exception Exception Failed to start the server
     */
    public void start()
            throws Exception {
        m_server = new SMBServer(m_config);
        m_config.addServer(m_server);
        m_server.startServer();

        long deadline = System.currentTimeMillis() + 10000L;
        while (true) {
            try (Socket sock = new Socket("127.0.0.1", m_port)) {
                return;
            }
            catch (IOException ex) {
                if (System.currentTimeMillis() > deadline)
                    throw new IOException("Test server did not start on port " + m_port, ex);
                Thread.sleep(20);
            }
        }
    }

    /**
     * Stop the server, it can be started again
     */
    public void stop() {
        if (m_server != null) {
            m_server.shutdownServer(false);
            m_config.removeAllServers();
            m_server = null;
        }
    }

    public int getPort() {
        return m_port;
    }

    /**
     * Return the local directory that is shared
     *
     * @return File
     */
    public File getShareDirectory() {
        return new File(m_root, "share");
    }

    @Override
    public void close() {
        stop();

        try (Stream<java.nio.file.Path> paths = Files.walk(m_root.toPath())) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
        }
        catch (IOException ex) {
            // Best effort clean up of the temporary directory
        }
    }
}
