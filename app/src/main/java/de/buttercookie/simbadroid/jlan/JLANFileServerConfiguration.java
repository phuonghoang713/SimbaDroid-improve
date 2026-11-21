/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package de.buttercookie.simbadroid.jlan;

import android.content.Context;
import android.net.LinkAddress;
import android.os.Build;
import android.os.Environment;

import androidx.annotation.Nullable;

import org.filesys.debug.DebugConfigSection;
import org.filesys.netbios.NetworkSettings;
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
import org.filesys.server.config.InvalidConfigurationException;
import org.filesys.server.config.SecurityConfigSection;
import org.filesys.server.config.ServerConfiguration;
import org.filesys.server.core.DeviceContextException;
import org.filesys.server.core.SharedDevice;
import org.filesys.server.filesys.DiskDeviceContext;
import org.filesys.server.filesys.DiskInterface;
import org.filesys.server.filesys.DiskSharedDevice;
import org.filesys.server.filesys.FilesystemsConfigSection;
import org.filesys.smb.DialectSelector;
import org.filesys.smb.server.SMBConfigSection;
import org.filesys.smb.server.SMBSrvSession;
import org.springframework.extensions.config.element.GenericConfigElement;

import java.io.File;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.EnumSet;
import java.util.Enumeration;

import de.buttercookie.simbadroid.BuildConfig;
import de.buttercookie.simbadroid.service.SmbService;
import de.buttercookie.simbadroid.settings.ServerSettings;
import de.buttercookie.simbadroid.util.FileUtils;
import de.buttercookie.simbadroid.util.SdCard;

public class JLANFileServerConfiguration extends ServerConfiguration {
    private static final int DefaultThreadPoolInit = 6;
    private static final int DefaultThreadPoolMax = 6;

    // The largest buffer size is what allows SMB 2.1 and later clients to read and write in chunks of 1 MB
    // instead of 64 KB, which makes a big difference to the transfer speed. These large buffers are only
    // allocated once a client actually uses them.
    private static final int[] DefaultMemoryPoolBufSizes = {256, 4096, 16384, 66000, 1049600};
    private static final int[] DefaultMemoryPoolInitAlloc = {20, 20, 5, 5, 0};
    private static final int[] DefaultMemoryPoolMaxAlloc = {100, 50, 50, 50, 8};

    public JLANFileServerConfiguration(Context context, String hostName, ServerSettings settings)
            throws InvalidConfigurationException, DeviceContextException {
        super(hostName);

        // Debug
        DebugConfigSection debugConfig = new DebugConfigSection(this);
        final GenericConfigElement debugConfigElement = new GenericConfigElement("output");
        debugConfig.setDebug("org.filesys.debug.ConsoleDebug", debugConfigElement);

        // Core
        CoreServerConfigSection coreConfig = new CoreServerConfigSection(this);
        coreConfig.setMemoryPool(DefaultMemoryPoolBufSizes, DefaultMemoryPoolInitAlloc,
                DefaultMemoryPoolMaxAlloc);
        coreConfig.setThreadPool(DefaultThreadPoolInit, DefaultThreadPoolMax);
        coreConfig.getThreadPool().setDebug(false);

        // Global
        GlobalConfigSection globalConfig = new GlobalConfigSection(this);

        // Security
        SecurityConfigSection secConfig = new SecurityConfigSection(this);
        DefaultAccessControlManager accessControlManager = new DefaultAccessControlManager();
        accessControlManager.setDebug(false);
        accessControlManager.initialize(this, new GenericConfigElement("aclManager"));
        secConfig.setAccessControlManager(accessControlManager);
        final UserAccountList userAccounts = new UserAccountList();
        final boolean requireLogin = settings.hasCredentials();
        if (requireLogin) {
            userAccounts.addUser(new UserAccount(settings.getUserName(), settings.getPassword()));
        }
        secConfig.setUserAccounts(userAccounts);

        // Shares
        FilesystemsConfigSection filesysConfig = new FilesystemsConfigSection(this);
        DiskInterface diskInterface = new SimbaDiskDriver();
        File sdCard = SdCard.findSdCardPath(context, null);
        if (sdCard != null) {
            addShare(diskInterface, this, filesysConfig, secConfig,
                    "External", sdCard.getAbsolutePath(),
                    FileUtils.getTrashcanPath(context, sdCard).getAbsolutePath(), true);
        }
        File internal = Environment.getExternalStorageDirectory();
        addShare(diskInterface, this, filesysConfig, secConfig,
                "Internal", internal.getAbsolutePath(),
                FileUtils.getTrashcanPath(context, internal).getAbsolutePath(), true);

        // SMB
        SMBConfigSection smbConfig = new SMBConfigSection(this);
        smbConfig.setServerName(hostName);
        smbConfig.setDomainName("WORKGROUP");
        smbConfig.setHostAnnounceInterval(5);
        smbConfig.setHostAnnouncer(true);
        smbConfig.setNameServerPort(SmbService.NETBIOS_NAME_PORT);
        smbConfig.setDatagramPort(SmbService.NETBIOS_DATAGRAM_PORT);
        smbConfig.setSessionPort(SmbService.NETBIOS_SESSION_PORT);
        smbConfig.setTcpipSMB(true);
        smbConfig.setTcpipSMBPort(SmbService.SMB_PORT);

        // SMB2 and SMB3 are always available. SMB1 is obsolete and insecure, but some old devices don't support
        // anything else, so it's up to the user whether to offer it.
        final DialectSelector dialects = new DialectSelector();
        if (settings.isSmb1Enabled()) {
            dialects.enableGroup(DialectSelector.DialectGroup.SMBv1);
        }
        dialects.enableGroup(DialectSelector.DialectGroup.SMBv2);
        dialects.enableGroup(DialectSelector.DialectGroup.SMBv3);
        smbConfig.setEnabledDialects(dialects);

        final SMBAuthenticator authenticator;
        if (requireLogin) {
            // Clients have to log in using the configured account. This also enables SMB2/3 clients to sign
            // and encrypt the connection, which requires a password that both sides know.
            authenticator = new LocalAuthenticator();
            authenticator.setAllowGuest(false);
        } else {
            // No credentials configured: let everybody in. SMB1 clients are treated as logged in whatever
            // they send, SMB2/3 clients get a guest session.
            authenticator = new LocalAuthenticator() {
                @Override
                public AuthStatus authenticateUser(ClientInfo client, SrvSession sess,
                                                   PasswordAlgorithm alg) {
                    return AuthStatus.AUTHENTICATED;
                }
            };
            authenticator.setAllowGuest(true);
        }
        authenticator.setDebug(false);
        authenticator.setAccessMode(ISMBAuthenticator.AuthMode.USER);
        final GenericConfigElement authenticatorConfigElement =
                new GenericConfigElement("authenticator");
        authenticator.initialize(this, authenticatorConfigElement);
        smbConfig.setAuthenticator(authenticator);
        smbConfig.setNetBIOSDebug(false);
        smbConfig.setHostAnnounceDebug(false);
        smbConfig.setSessionDebugFlags(EnumSet.noneOf(SMBSrvSession.Dbg.class));
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            // Core lib desugaring is missing some bits in the network code
            smbConfig.setDisableNIOCode(true);
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || BuildConfig.FLAVOR.equals("oldApi")) {
            // Core lib desugaring doesn't handle the Java 1.8 method signature change in
            // ConcurrentHashMap.keySet() and native support was only introduced with API29.

            // Additionally, if core lib desugaring is enabled with a minApi <= 23, it includes a
            // copy of the Java 1.7 implementation of ConcurrentHashMap which then shadows the 1.8
            // version even on API29+ devices, hence the need for separate build flavours.
            smbConfig.setDisableHashedOpenFileMap(true);
        }
    }

    void setBindAddress(LinkAddress bindAddress) throws InvalidConfigurationException {
        final SMBConfigSection smbConfig =
                (SMBConfigSection) getConfigSection(SMBConfigSection.SectionName);

        smbConfig.setSMBBindAddress(bindAddress.getAddress());
        smbConfig.setNetBIOSBindAddress(bindAddress.getAddress());

        String broadcastAddress = getBroadcastAddress(bindAddress);
        if (broadcastAddress != null) {
            smbConfig.setBroadcastMask(broadcastAddress);
            NetworkSettings.setBroadcastMask(broadcastAddress);
        }
    }

    private static String getBroadcastAddress(LinkAddress address) {
        String broadcastAddress = null;
        if (address.getAddress() instanceof Inet4Address v4addr) {
            try {
                InterfaceAddress ifAddr = convertToInterfaceAddress(v4addr);
                // Point-to-point links and the like don't have a broadcast address
                if (ifAddr != null && ifAddr.getBroadcast() != null) {
                    broadcastAddress = ifAddr.getBroadcast().getHostAddress();
                }
            } catch (SocketException ignored) {}
        } else if (address.getAddress() instanceof Inet6Address) {
            broadcastAddress = "ff02::1";
        }
        return broadcastAddress;
    }

    @Nullable
    private static InterfaceAddress convertToInterfaceAddress(InetAddress address) throws SocketException {
        // The interface might just have gone away again
        NetworkInterface networkInterface = NetworkInterface.getByInetAddress(address);
        if (networkInterface == null) {
            return null;
        }
        return networkInterface.getInterfaceAddresses().stream()
                .filter(addr -> address.equals(addr.getAddress()))
                .findFirst().orElse(null);
    }

    private static void addShare(DiskInterface diskInterface,
                                 ServerConfiguration serverConfig,
                                 FilesystemsConfigSection filesysConfig,
                                 SecurityConfigSection secConfig,
                                 String shareName, String sharePath, @Nullable String trashcanPath,
                                 boolean caseInsensitive)
            throws DeviceContextException {
        final GenericConfigElement driverConfig = new GenericConfigElement("driver");
        final GenericConfigElement localPathConfig = new GenericConfigElement("LocalPath");
        localPathConfig.setValue(sharePath);
        driverConfig.addChild(localPathConfig);
        if (trashcanPath != null) {
            final GenericConfigElement trashcanPathConfig =
                    new GenericConfigElement("TrashcanPath");
            trashcanPathConfig.setValue(trashcanPath);
            driverConfig.addChild(trashcanPathConfig);
        }
        if (caseInsensitive) {
            driverConfig.addChild(new GenericConfigElement("DiskIsCaseInsensitive"));
        }
        DiskDeviceContext diskDeviceContext =
                (DiskDeviceContext) diskInterface.createContext(shareName, driverConfig);
        diskDeviceContext.setShareName(shareName);
        diskDeviceContext.setConfigurationParameters(driverConfig);
        diskDeviceContext.enableChangeHandler(false);
        DiskSharedDevice diskDev = new DiskSharedDevice(shareName, diskInterface, diskDeviceContext);
        diskDev.setConfiguration(serverConfig);
        diskDev.setAccessControlList(secConfig.getGlobalAccessControls());
        diskDeviceContext.startFilesystem(diskDev);
        filesysConfig.addShare(diskDev);
    }

    void removeTrashcanFolders() {
        final FilesystemsConfigSection filesysConfig =
                (FilesystemsConfigSection) getConfigSection(FilesystemsConfigSection.SectionName);

        Enumeration<SharedDevice> shares = filesysConfig.getShares().enumerateShares();
        while (shares.hasMoreElements()) {
            SharedDevice share = shares.nextElement();
            if (share.getContext() instanceof SimbaDiskDeviceContext diskContext) {
                diskContext.removeTrashcanFolderIfEmpty();
            }
        }
    }
}
