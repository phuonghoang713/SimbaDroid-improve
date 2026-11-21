/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package de.buttercookie.simbadroid.service;

import static de.buttercookie.simbadroid.Intents.ACTION_STOP;
import static de.buttercookie.simbadroid.util.Iptables.iptables;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.net.wifi.WifiManager;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.ServiceCompat;

import org.filesys.smb.TcpipSMB;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import de.buttercookie.simbadroid.MainActivity;
import de.buttercookie.simbadroid.R;
import de.buttercookie.simbadroid.jlan.JLANFileServer;
import de.buttercookie.simbadroid.permissions.Permissions;
import de.buttercookie.simbadroid.settings.ServerSettings;
import de.buttercookie.simbadroid.util.IpSort;
import de.buttercookie.simbadroid.util.Iptables;
import de.buttercookie.simbadroid.util.ThreadUtils;

public class SmbService extends Service {
    private static final String LOGTAG = "SmbService";

    private static final String NOTIFICATION_CHANNEL = SmbService.class.getName();
    private static final int NOTIFICATION_ID = 1;
    private static final long NETWORK_UNAVAILABLE_STARTUP_TIMEOUT_MS = 5 * 60 * 1000;
    private static final long NETWORK_UNAVAILABLE_TIMEOUT_MS = 20 * 60 * 1000;
    private static final String UNC_PREFIX = "\\\uFEFF\\";
    private static final String MDNS_SUFFIX = ".local";

    /**
     * The ports that the server listens on. Ports below 1024 can only be opened by root, so the server always
     * uses unprivileged ports. On rooted devices the standard ports are redirected to them.
     */
    public static final int SMB_PORT = 4450;
    public static final int NETBIOS_NAME_PORT = 1137;
    public static final int NETBIOS_DATAGRAM_PORT = 1138;
    public static final int NETBIOS_SESSION_PORT = 1139;

    private static final String[] PORT_REDIRECT_RULES = {
            "PREROUTING -p tcp --dport 445 -j REDIRECT --to-port " + SMB_PORT,
            "PREROUTING -p udp --dport 137 -j REDIRECT --to-port " + NETBIOS_NAME_PORT,
            "PREROUTING -p udp --dport 138 -j REDIRECT --to-port " + NETBIOS_DATAGRAM_PORT,
            "PREROUTING -p tcp --dport 139 -j REDIRECT --to-port " + NETBIOS_SESSION_PORT,
    };

    // The DNS-SD service type that SMB clients such as macOS Finder and Linux file managers browse for
    private static final String NSD_SERVICE_TYPE = "_smb._tcp.";

    private final IBinder binder = new SmbBinder();

    public class SmbBinder extends Binder {
        SmbService getService() {
            return SmbService.this;
        }
    }

    private boolean mRunning = false;
    // The local networks that are currently connected, and our IPv4 address on them (if we have one)
    private final Map<Network, LinkAddress> mAvailableNetworks = new LinkedHashMap<>();
    // The network that we are serving on
    private Network mNetwork = null;
    private LinkAddress mLinkAddress = null;
    // The address that the server has been started on
    private LinkAddress mServerAddress = null;

    private JLANFileServer mServer;
    private ServerSettings mSettings;
    private PowerManager.WakeLock mWakeLock;
    private WifiManager.WifiLock mWifiLock;
    private WifiManager.MulticastLock mMulticastLock;

    // Whether the standard SMB ports are being redirected to our ports, which requires root
    private boolean mPortRedirectActive = false;
    // Incremented each time the server is started, to ignore the result of an outdated port redirect setup
    private int mStartGeneration = 0;

    private ConnectivityManager.NetworkCallback mNetCallback;
    private Runnable mNetworkTimeoutRunnable;
    private long mNetworkTimeoutMs = NETWORK_UNAVAILABLE_STARTUP_TIMEOUT_MS;

    private NsdManager.RegistrationListener mNsdRegistrationListener;
    private String mMDNSHostname;
    private static final int INITIAL_SERVICE_NAME_SUFFIX = 1;
    private int mServiceNameSuffix = INITIAL_SERVICE_NAME_SUFFIX;

    /**
     * @param serviceRunning  The user has started the server.
     * @param serverRunning   The server is running and reachable, i.e. there is a network connection.
     * @param mdnsHost        The <code>.local</code> host name of the server, or <code>null</code>.
     * @param netBiosAddress  The UNC path of the server using its NetBIOS name.
     * @param ipAddress       The IP address of the server, or an empty string.
     * @param port            The TCP port that clients need to connect to.
     * @param standardPort    Whether <code>port</code> is the standard SMB port, so clients don't need to be told
     *                        about it.
     * @param userName        The user name that clients need to log in with, or <code>null</code> if the server
     *                        doesn't require a login.
     */
    public record Status(boolean serviceRunning, boolean serverRunning, String mdnsHost,
                         String netBiosAddress, String ipAddress, int port, boolean standardPort,
                         String userName) {
        /** @return The UNC path of the server using its mDNS host name, or <code>null</code>. */
        public String mdnsAddress() {
            return mdnsHost != null ? UNC_PREFIX + mdnsHost : null;
        }

        /** @return The UNC path of the server using its IP address, or an empty string. */
        public String ipUncAddress() {
            return !ipAddress.isEmpty() ? UNC_PREFIX + ipAddress : "";
        }
    }

    private void setIsRunning(boolean isRunning) {
        if (mRunning != isRunning) {
            mRunning = isRunning;
            updateServerState();
        }
    }

    private void setLinkAddress(LinkAddress address) {
        if (!Objects.equals(mLinkAddress, address)) {
            mLinkAddress = address;
            if (address != null) {
                mNetworkTimeoutMs = NETWORK_UNAVAILABLE_TIMEOUT_MS;
            }
            updateServerState();
        }
    }

    private void setMDNSHostname(String hostname) {
        ThreadUtils.assertOnUiThread();
        mMDNSHostname = hostname;
        InetAddress addr = mLinkAddress != null ? mLinkAddress.getAddress() : null;
        HostnameBroadcaster.setHostname(addr, hostname);
    }

    private int getClientPort() {
        return mPortRedirectActive ? TcpipSMB.PORT : SMB_PORT;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        initLocks();
        monitorNetwork();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        updateUI();
        return binder;
    }

    @SuppressLint("InlinedApi")
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (handleAction(intent) || mRunning) {
            return START_NOT_STICKY;
        }

        Notification notification = getServiceNotification();
        try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_MANIFEST);
        } catch (RuntimeException e) {
            // Since Android 12 a foreground service can't be started while the app is in the background
            Log.e(LOGTAG, "Couldn't start the foreground service", e);
            reportStartupError();
            return START_NOT_STICKY;
        }

        try {
            mSettings = ServerSettings.load(this);
            mServer = new JLANFileServer(this, getString(R.string.dns_name), mSettings);
        } catch (Exception e) {
            Log.e(LOGTAG, "Couldn't create the SMB server", e);
            mServer = null;
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE);
            reportStartupError();
            return START_NOT_STICKY;
        }

        acquireLocks();
        setupPortRedirect();
        setIsRunning(true);

        return START_NOT_STICKY;
    }

    private void reportStartupError() {
        Toast.makeText(this, R.string.toast_error_starting_server, Toast.LENGTH_SHORT).show();
        stopSelf();
    }

    private boolean handleAction(@Nullable Intent intent) {
        boolean handled = false;
        final String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) {
            stop();
            handled = true;
        }
        return handled;
    }

    public void stop() {
        if (!mRunning) {
            return;
        }

        shutdown();

        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    /**
     * Stop the server and release everything that was acquired for running it.
     */
    private void shutdown() {
        setIsRunning(false);
        removePortRedirect();
        releaseLocks();
        mServer = null;
    }

    @Override
    public void onDestroy() {
        if (mRunning) {
            // The service is being destroyed without having been stopped first
            shutdown();
        }
        unregisterNsdService();
        unmonitorNetwork();
        stopNetworkTimeout();
        updateUI();
        super.onDestroy();
    }

    public boolean isRunning() {
        return mRunning;
    }

    public boolean isNetworkAvailable() {
        return mLinkAddress != null;
    }

    /**
     * On rooted devices redirect the standard SMB ports to the ports that the server is listening on.
     * <p>
     * Getting a root shell can take a long time, especially if the user has to confirm a superuser prompt
     * first, so this is done in the background. Until it has finished - and on devices without root - clients
     * have to use our non-standard port.
     */
    private void setupPortRedirect() {
        final int generation = ++mStartGeneration;
        ThreadUtils.postToBackgroundThread(() -> {
            boolean active = false;
            try {
                if (Iptables.hasRoot()) {
                    active = true;
                    for (String rule : PORT_REDIRECT_RULES) {
                        // The first rule is the one for the SMB port, which is the one that matters
                        boolean added = iptables(false, "nat", "A", rule);
                        if (rule.equals(PORT_REDIRECT_RULES[0])) {
                            active = added;
                        }
                    }
                }
            } catch (RuntimeException e) {
                Log.w(LOGTAG, "Couldn't set up the port redirect", e);
                active = false;
            }

            final boolean redirectActive = active;
            ThreadUtils.postToUiThread(() -> {
                if (mRunning && generation == mStartGeneration) {
                    setPortRedirectActive(redirectActive);
                } else if (redirectActive && !mRunning) {
                    // The server has been stopped in the meantime. (If it has been started again as well, the
                    // setup belonging to that start takes care of the rules.)
                    removePortRedirectRules();
                }
            });
        });
    }

    private void setPortRedirectActive(boolean active) {
        if (mPortRedirectActive != active) {
            mPortRedirectActive = active;
            // The port that clients need to use has changed
            if (mNsdRegistrationListener != null) {
                unregisterNsdService();
                registerNsdService();
            }
            updateUI();
        }
    }

    private void removePortRedirect() {
        // Invalidate a setup that might still be in progress
        mStartGeneration++;
        if (mPortRedirectActive) {
            mPortRedirectActive = false;
            removePortRedirectRules();
        }
    }

    private static void removePortRedirectRules() {
        ThreadUtils.postToBackgroundThread(() -> {
            try {
                for (String rule : PORT_REDIRECT_RULES) {
                    iptables(false, "nat", "D", rule);
                }
            } catch (RuntimeException e) {
                Log.w(LOGTAG, "Couldn't remove the port redirect", e);
            }
        });
    }

    private void updateServerState() {
        ThreadUtils.assertOnUiThread();
        updateUI();
        if (isNetworkAvailable()) {
            stopNetworkTimeout();
        } else if (mRunning) {
            startNetworkTimeout();
        } else {
            stopNetworkTimeout();
        }

        if (mServer == null) {
            return;
        }

        if (mRunning && isNetworkAvailable()) {
            if (mServer.running() && !Objects.equals(mServerAddress, mLinkAddress)) {
                // The server is bound to a specific address, so it needs to be restarted on the new one
                Log.d(LOGTAG, "Network address changed, restarting SMB server");
                mServer.stop();
            }

            Log.d(LOGTAG, "Starting SMB server");
            try {
                mServer.setBindAddress(mLinkAddress);
                mServer.start();
                mServerAddress = mLinkAddress;
            } catch (RuntimeException e) {
                Log.e(LOGTAG, "Couldn't start the SMB server", e);
                Toast.makeText(this, R.string.toast_error_starting_server, Toast.LENGTH_SHORT).show();
            }
            getSystemService(NotificationManager.class)
                    .notify(NOTIFICATION_ID, getServiceNotification());
            registerNsdService();
            if (mMDNSHostname != null) {
                // Make sure that the host name is advertised on the current address
                setMDNSHostname(mMDNSHostname);
            }
        } else {
            Log.d(LOGTAG, "Stopping SMB server");
            mServer.stop();
            mServerAddress = null;
            if (mRunning && !isNetworkAvailable()) {
                getSystemService(NotificationManager.class)
                        .notify(NOTIFICATION_ID, getServiceNotification());
            }
            unregisterNsdService();
        }
        updateUI();
    }

    private void startNetworkTimeout() {
        stopNetworkTimeout();
        mNetworkTimeoutRunnable = this::stop;
        ThreadUtils.postDelayedToUiThread(mNetworkTimeoutRunnable, mNetworkTimeoutMs);
    }

    private void stopNetworkTimeout() {
        if (mNetworkTimeoutRunnable != null) {
            ThreadUtils.removeCallbacksFromUiThread(mNetworkTimeoutRunnable);
            mNetworkTimeoutRunnable = null;
        }
    }

    @SuppressWarnings("deprecation")
    private void initLocks() {
        final String tag = getString(R.string.app_name) + "::SmbService";

        PowerManager pwrMgr = getSystemService(PowerManager.class);
        mWakeLock = pwrMgr.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, tag);
        mWakeLock.setReferenceCounted(false);

        // WIFI_MODE_FULL has no effect whatsoever since Android 10. The high performance mode keeps Wi-Fi out
        // of power save mode while the screen is off, which otherwise makes the server slow to respond or
        // unreachable. From Android 14 the system maps it to the low latency mode.
        WifiManager wifiMgr = getApplicationContext().getSystemService(WifiManager.class);
        // Devices without Wi-Fi, e.g. ones that only have Ethernet, have no Wi-Fi manager
        if (wifiMgr != null) {
            mWifiLock = wifiMgr.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, tag);
            mWifiLock.setReferenceCounted(false);

            // Without a multicast lock many devices filter out the mDNS queries for our host name
            mMulticastLock = wifiMgr.createMulticastLock(tag);
            mMulticastLock.setReferenceCounted(false);
        }
    }

    @SuppressLint("WakelockTimeout")
    private void acquireLocks() {
        mWakeLock.acquire();
        if (mWifiLock != null) {
            mWifiLock.acquire();
        }
        if (mMulticastLock != null) {
            mMulticastLock.acquire();
        }
    }

    private void releaseLocks() {
        if (mMulticastLock != null && mMulticastLock.isHeld()) {
            mMulticastLock.release();
        }
        if (mWifiLock != null && mWifiLock.isHeld()) {
            mWifiLock.release();
        }
        if (mWakeLock.isHeld()) {
            mWakeLock.release();
        }
    }

    private void monitorNetwork() {
        if (mNetCallback == null) {
            ConnectivityManager connMgr = getSystemService(ConnectivityManager.class);
            mNetCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(@NonNull Network network) {
                    // The addresses usually arrive via onLinkPropertiesChanged(), but check here as well
                    onLinkProperties(network, connMgr.getLinkProperties(network));
                }

                @Override
                public void onLinkPropertiesChanged(@NonNull Network network,
                                                    @NonNull LinkProperties linkProperties) {
                    onLinkProperties(network, linkProperties);
                }

                @Override
                public void onLost(@NonNull Network network) {
                    ThreadUtils.postToUiThread(() -> onNetworkLost(network));
                }

                private void onLinkProperties(Network network, @Nullable LinkProperties props) {
                    final LinkAddress address = props == null ? null :
                            props.getLinkAddresses().stream()
                                    .filter(addr -> addr.getAddress() instanceof Inet4Address)
                                    .min(new IpSort.LinkAddressComparator(false))
                                    .orElse(null);
                    ThreadUtils.postToUiThread(() -> onNetworkAddress(network, address));
                }
            };
            final NetworkRequest request = new NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                    .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
                    .build();
            try {
                connMgr.requestNetwork(request, mNetCallback);
            } catch (RuntimeException e) {
                // The system limits the number of requests per app and can refuse the request for other reasons.
                // Just watching the networks, without asking for one to be kept up, is the next best thing.
                Log.w(LOGTAG, "Couldn't request the local network", e);
                try {
                    connMgr.registerNetworkCallback(request, mNetCallback);
                } catch (RuntimeException e2) {
                    Log.e(LOGTAG, "Couldn't monitor the network", e2);
                    mNetCallback = null;
                }
            }
        }
    }

    private void onNetworkAddress(Network network, @Nullable LinkAddress address) {
        if (mNetCallback == null) {
            // No longer monitoring the network
            return;
        }
        mAvailableNetworks.put(network, address);
        selectNetwork();
    }

    private void onNetworkLost(Network network) {
        if (mNetCallback == null) {
            return;
        }
        mAvailableNetworks.remove(network);
        selectNetwork();
    }

    /**
     * Choose the network to serve on. We stay on the current network for as long as we have an address there,
     * otherwise we switch to another connected network that has one.
     */
    private void selectNetwork() {
        Network network = mNetwork;
        LinkAddress address = network != null ? mAvailableNetworks.get(network) : null;

        if (address == null) {
            network = null;
            for (Map.Entry<Network, LinkAddress> entry : mAvailableNetworks.entrySet()) {
                if (entry.getValue() != null) {
                    network = entry.getKey();
                    address = entry.getValue();
                    break;
                }
            }
        }

        if (!Objects.equals(network, mNetwork)) {
            mNetwork = network;
            // Make sure that our sockets use the local network, even if it doesn't provide internet access
            getSystemService(ConnectivityManager.class).bindProcessToNetwork(network);
        }
        setLinkAddress(address);
    }

    private void unmonitorNetwork() {
        if (mNetCallback != null) {
            ConnectivityManager connMgr = getSystemService(ConnectivityManager.class);
            mLinkAddress = null;
            mNetwork = null;
            mAvailableNetworks.clear();
            try {
                connMgr.unregisterNetworkCallback(mNetCallback);
            } catch (RuntimeException e) {
                Log.w(LOGTAG, "Couldn't stop monitoring the network", e);
            }
            connMgr.bindProcessToNetwork(null);
            mNetCallback = null;
        }
    }

    private void registerNsdService() {
        if (mNsdRegistrationListener == null) {
            final String serviceName = getNsdServiceName(mServiceNameSuffix);

            NsdServiceInfo serviceInfo = new NsdServiceInfo();
            serviceInfo.setServiceName(serviceName);
            serviceInfo.setServiceType(NSD_SERVICE_TYPE);
            // Advertise the port that clients can actually reach, which is only the standard SMB port if we
            // were able to redirect it.
            serviceInfo.setPort(getClientPort());

            final NsdManager.RegistrationListener listener = new NsdManager.RegistrationListener() {
                // The callbacks are invoked on a thread of the NSD manager, all our state is handled on the
                // UI thread.
                @Override
                public void onServiceRegistered(NsdServiceInfo serviceInfo) {
                    final String registeredName = serviceInfo.getServiceName();
                    ThreadUtils.postToUiThread(() -> {
                        if (mNsdRegistrationListener != this) {
                            // Already unregistered again
                            return;
                        }
                        // Android auto-increments the service name on detecting a collision, but it
                        // does so by appending a " (<digit>)" suffix (i.e. including a space) to the
                        // service name, making the resulting name not plain-DNS-friendly.
                        if (!serviceName.equals(registeredName)) {
                            // We couldn't get our preferred service name, so try again with a suffix
                            mServiceNameSuffix++;
                            unregisterNsdService();
                            registerNsdService();
                        } else {
                            setMDNSHostname(serviceName);
                            updateUI();
                        }
                    });
                }

                @Override
                public void onRegistrationFailed(NsdServiceInfo serviceInfo, int errorCode) {
                    clearHostname();
                }

                @Override
                public void onServiceUnregistered(NsdServiceInfo serviceInfo) {
                    clearHostname();
                }

                @Override
                public void onUnregistrationFailed(NsdServiceInfo serviceInfo, int errorCode) {
                    clearHostname();
                }

                private void clearHostname() {
                    ThreadUtils.postToUiThread(() -> {
                        // Ignore callbacks of a registration that has been replaced by a new one
                        if (mNsdRegistrationListener == null || mNsdRegistrationListener == this) {
                            setMDNSHostname(null);
                            updateUI();
                        }
                    });
                }
            };
            mNsdRegistrationListener = listener;

            try {
                NsdManager nsdManager = getSystemService(NsdManager.class);
                nsdManager.registerService(
                        serviceInfo, NsdManager.PROTOCOL_DNS_SD, listener);
            } catch (RuntimeException e) {
                Log.w(LOGTAG, "Couldn't register the mDNS service", e);
                mNsdRegistrationListener = null;
            }
        }
    }

    private void unregisterNsdService() {
        if (mNsdRegistrationListener != null) {
            NsdManager.RegistrationListener listener = mNsdRegistrationListener;
            mNsdRegistrationListener = null;
            try {
                NsdManager nsdManager = getSystemService(NsdManager.class);
                nsdManager.unregisterService(listener);
            } catch (RuntimeException e) {
                Log.w(LOGTAG, "Couldn't unregister the mDNS service", e);
            }
            setMDNSHostname(null);
        }
    }

    private String getNsdServiceName(int suffix) {
        StringBuilder sb = new StringBuilder(getString(R.string.dns_name));
        if (suffix > INITIAL_SERVICE_NAME_SUFFIX) {
            sb.append("-");
            sb.append(suffix);
        }
        return sb.toString();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            String name = getString(R.string.notification_channel_name);
            String description = getString(R.string.notification_channel_description);
            int importance = NotificationManager.IMPORTANCE_LOW;
            NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL, name, importance);
            channel.setDescription(description);

            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(channel);
        }
    }

    private Notification getServiceNotification() {
        Intent activityIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(getApplicationContext(), 0,
                activityIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
                .setSmallIcon(R.drawable.ic_notification)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getServiceNotificationText())
                .setContentIntent(pendingIntent)
                .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
                .setOngoing(true);
        NotificationCompat.Action stopAction = getStopAction();
        if (stopAction != null) {
            builder.addAction(stopAction);
        }
        return builder.build();
    }

    private @Nullable NotificationCompat.Action getStopAction() {
        NotificationCompat.Action action = null;
        if (isNetworkAvailable()) {
            Intent stopIntent = new Intent(this, SmbService.class)
                    .setAction(ACTION_STOP);
            PendingIntent pendingIntent = PendingIntent.getService(getApplicationContext(), 0,
                    stopIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            action = new NotificationCompat.Action.Builder(R.drawable.ic_stop,
                    getString(R.string.notification_action_stop), pendingIntent)
                    .build();
        }
        return action;
    }

    private String getServiceNotificationText() {
        return isNetworkAvailable() ?
                getString(R.string.message_server_running) :
                getString(R.string.message_server_waiting_network);
    }

    /**
     * Start the service, optionally prompting for the necessary permissions.
     *
     * @param context Must be an <code>Activity</code> context if <code>promptForPermissions</code>
     *                is <code>true</code>.
     * @param promptForPermissions Whether to prompt for the required Android permissions.
     */
    @SuppressLint("InlinedApi")
    public static void startService(final Context context, final boolean promptForPermissions) {
        // Don't hold on to an activity for longer than necessary
        final Context appContext = context.getApplicationContext();
        Intent intent = new Intent(appContext, SmbService.class);

        var notifPerm = Permissions.from(context);
        if (!promptForPermissions) {
            notifPerm.doNotPrompt();
        }
        notifPerm.withPermissions(Manifest.permission.POST_NOTIFICATIONS)
                .alwaysRun(() -> ThreadUtils.postToUiThread(() -> {
                    String storagePermission =
                            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R ?
                                    Manifest.permission.MANAGE_EXTERNAL_STORAGE :
                                    Manifest.permission.WRITE_EXTERNAL_STORAGE;
                    var storagePerm = Permissions.from(context);
                    if (!promptForPermissions) {
                        storagePerm.doNotPrompt();
                    }
                    storagePerm.withPermissions(storagePermission)
                            .andFallback(() -> Toast.makeText(appContext,
                                    R.string.toast_need_storage_permission,
                                    Toast.LENGTH_SHORT).show())
                            .run(() -> launchService(appContext, intent));
                }));
    }

    private static void launchService(Context appContext, Intent intent) {
        try {
            appContext.startService(intent);
        } catch (RuntimeException e) {
            // E.g. the app has gone into the background while the permission prompts were showing
            Log.e(LOGTAG, "Couldn't start the service", e);
            Toast.makeText(appContext, R.string.toast_error_starting_server,
                    Toast.LENGTH_SHORT).show();
        }
    }

    private void updateUI() {
        boolean serverStarted = mServer != null && mServer.running();
        String netBiosAddress = UNC_PREFIX + getString(R.string.dns_name);
        String textualIp = mLinkAddress != null ?
                mLinkAddress.getAddress().getHostAddress() : "";
        String mdnsHost = mMDNSHostname != null ? mMDNSHostname + MDNS_SUFFIX : null;
        String userName = mRunning && mSettings != null && mSettings.hasCredentials() ?
                mSettings.getUserName() : null;

        Status status = new Status(mRunning, serverStarted, mdnsHost, netBiosAddress, textualIp,
                getClientPort(), mPortRedirectActive, userName);

        var liveData = SmbServiceStatusLiveData.get();
        if (!status.equals(liveData.getValue())) {
            if (ThreadUtils.isOnUiThread()) {
                liveData.setValue(status);
            } else {
                liveData.postValue(status);
            }
        }
    }
}
