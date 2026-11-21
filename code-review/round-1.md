# Review findings, round 1

Each finding has an identifier (`A` = Android app, `L` = JFileServer library), a severity and a status.
The fixes are described in more detail in [improve/](improve/README.md), and how they were checked in
[verification.md](verification.md).

Severity:

* **High** - the feature does not work, data can be damaged, or the app hangs or stops responding.
* **Medium** - works, but unreliably or badly under conditions that occur in normal use.
* **Low** - only affects unusual situations, or is cosmetic.
* **Info** - not a defect as such, but worth changing.

## Android app

### A1 - Granting "All files access" was never noticed (High, fixed)

`MainActivity.onActivityResult()` compared the **result** code with the constant that was used as the **request**
code when opening the system settings screen. The settings screen always returns `RESULT_CANCELED`, so the branch
was never taken.

Effect on Android 11 and later: after the user granted "All files access" and came back, nothing happened and the
server did not start. Worse, the permission request stayed in the internal queue of pending prompts for ever. Any
later request that needed a prompt (for example the notification permission, if it had been denied) was put behind
it and never shown, so the *Start server* button silently did nothing until the app was restarted.

Fix: compare the request code. The misleading constant was renamed to `ACTIVITY_MANAGE_STORAGE_REQUEST_CODE`.

### A2 - Root shell commands ran on the main thread (High, fixed)

`SmbService.onStartCommand()` and `stop()` ran six `iptables` commands through libsu on the main thread. The first
command starts the shell, which on a rooted device waits for the superuser prompt to be answered, and on any device
blocks while processes are started. That freezes the UI and can end in an "app is not responding" dialog.

Fix: the port redirect is set up and removed on the background thread. The service is told the outcome, so it knows
whether the standard SMB port is usable.

### A3 - Without root the app advertised and displayed an address that does not work (High, fixed)

Without root the server can only listen on port 4450. Nevertheless the app

* registered its DNS-SD service on port 445, where nothing was listening, and
* showed `\\simbadroid.local`, `\\simbadroid` and `\\<ip>` with no hint that a port has to be entered.

Fix: the service is registered as `_smb._tcp` (the type that macOS and Linux file managers browse for) with the port
that clients can really reach, and the status text shows the address and port, with an example. See
[improve/not-rooted.md](improve/not-rooted.md).

### A4 - The Wi-Fi lock had no effect on Android 10 and later (Medium, fixed)

`WIFI_MODE_FULL` has been a no-op since Android 10, so nothing stopped Wi-Fi from going into power save mode when
the screen turned off, which makes a server slow to reach or unreachable. The lock is now
`WIFI_MODE_FULL_HIGH_PERF`. There was also no multicast lock, without which many devices drop the mDNS queries for
the `simbadroid.local` name; one is now held while the server runs.

### A5 - Several ways to crash on start (Medium, fixed)

* An exception while building the server configuration (for example a storage problem) was rethrown as a
  `RuntimeException` and crashed the app.
* `NetworkInterface.getByInetAddress()` returns `null` if the interface has just gone away, and
  `getBroadcast()` returns `null` on links without a broadcast address. Both were dereferenced.
* `startForeground()` can throw since Android 12 when the app is not in the foreground.

All three are now handled: the user sees the "Error starting server" message instead of a crash.

### A6 - Network changes were not followed properly (Medium, fixed)

* The IP address was only read in `onAvailable()`, at which point it is often not assigned yet, and later changes
  were not noticed.
* If the address changed the server kept listening on the old one.
* When any network was lost the server was stopped, even if it was running on another network that was still
  connected.

The service now tracks every connected Wi-Fi/Ethernet network with its address, follows
`onLinkPropertiesChanged()`, restarts the server when its address changes and only reacts to the loss of the network
it is actually using.

### A7 - Bouncy Castle was installed as the preferred crypto provider (Medium, fixed)

`Application` inserted Bouncy Castle at position 1, so *every* cryptographic operation used its pure Java code
instead of the platform's native, hardware accelerated implementation. For SMB1 that hardly mattered. For SMB2/3
it matters a great deal, because every packet is signed or encrypted. The provider is now added at the end of the
list: it still supplies the old algorithms that SMB1 needs (MD4, DES), and everything else uses the platform.

### A8 - Resources were not released if the service was destroyed while running (Low, fixed)

`onDestroy()` did not stop the server, release the wake locks or remove the port redirect. It now does.

### A9 - Service state was modified from a system thread (Low, fixed)

The DNS-SD registration callbacks run on a thread of the system service and changed fields that are otherwise only
used on the main thread. They now post to the main thread, and stale callbacks of a registration that has already
been replaced are ignored. `getNsdServiceName()` also ignored its parameter.

### A10 - The host name broadcaster ignored address changes (Low, fixed)

`HostnameBroadcaster` only restarted when the name changed, so after an address change `simbadroid.local` kept
pointing at the old address.

### A11 - The start button could stay disabled (Low, fixed)

The button state depends on being bound to the service, but it was only updated when the status changed, which
normally happens before the binding is reported. After the activity was recreated the button could therefore look
disabled although the server could be started.

### A12 - Errors after the fact were reported as failures (Low, fixed)

`SimbaDiskDriver.renameFile()` renames the file and then restores its modification time. If only the second step
failed the client was told that the rename failed, although it had happened. `getDiskInformation()` threw an
unchecked exception if the volume had disappeared.

### A13 - A permission request could stay pending for ever (Low, fixed)

If the device has no settings screen for "All files access", the fallback could throw, or do nothing, without
resolving the pending request (compare A1).

### A14 - Backup rules were the unedited template (Info, fixed)

The new settings file contains the access password and is excluded from cloud backup and device transfer.

### A15 - Missing declaration for the "special use" foreground service (Info, fixed)

Android 14 expects a `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` entry describing what the service does.

### A16 - Shares were reported as FAT (Info, fixed)

Clients were told that the file system is FAT. Windows can refuse to copy files larger than 4 GB to a share that
reports FAT, although the limit does not apply here. The shares now report NTFS, as Samba does.

## JFileServer library

### L1 - Only SMB1 was supported (High, fixed)

Windows has not installed an SMB1 client by default since 2017, and macOS, current Linux desktops and most Android
apps prefer or require SMB2. The library now implements SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1. See
[improve/smb2-smb3.md](improve/smb2-smb3.md) and [../architecture/smb2.md](../architecture/smb2.md).

### L2 - Concurrent requests on one file handle could return or store the wrong data (High, fixed)

`JavaNIONetworkFile` read and wrote by first moving the file position of the shared channel and then doing the I/O.
Two requests on the same handle running at the same time could interleave, so that one of them used the position
set by the other. Clients do send several reads or writes for one handle at once, SMB2 clients in particular. The
test `SmbjFeatureTest.testConcurrentIo` reproduced it on the unpatched code (1 corrupt read in 1,200).

Fix: positional reads and writes, which do not use the channel position at all.

### L3 - Overwriting an existing large file failed (High, fixed)

To truncate a file of 500 MB or more to zero length, the driver moves it to the trashcan folder (to be deleted in
the background) and then reopens the path "creating" a new file. The reopen ignored the create flag, so it failed
with "file not found". In practice: copying a large file over an existing one failed. This affects SMB1 as well.
Reproduced by `SmbjFeatureTest.testOverwriteLarge`.

### L4 - The server could fail to come back after a restart (High, fixed)

`shutdownServer()` returned while the thread that owns the listening socket was still running. The app stops and
immediately restarts the server when the network changes; if the old socket was still open the new server could not
bind the port, without any error being visible. Reproduced by `ServerLifecycleTest`.

Fix: stopping the connections handler now waits until the sockets are closed.

### L5 - Socket I/O used busy loops (Medium, fixed)

The channels are non-blocking, and both the read of the remainder of a request and the write of a response looped
without waiting until the data had been transferred. A worker thread therefore used 100% of a CPU core for the
whole duration of an upload, and whenever the client was slower than the server during a download. That costs
battery and heat on a phone. A client that stopped reading also kept a thread spinning for ever.

Fix: yield briefly, then sleep in 0.5 ms steps, and give up on a client that makes no progress for 60 seconds.

### L6 - Directory listings stopped at the first unreadable entry (Medium, fixed)

If the attributes of one entry could not be read (a file deleted during the listing, a broken link, a folder that
Android does not let the app look into), the listing ended there and the remaining entries were silently missing.
Such entries are now skipped. Reading the attributes also took five system calls per entry; it now takes two, which
is noticeable in folders with thousands of files.

### L7 - No limit on the size of a request before logon (Medium, fixed)

A client could announce a request of up to the largest buffer size as its very first message and make the server
allocate it. With the 1 MB buffers that SMB2 needs this would have become an easy way to exhaust the memory of a
phone. Requests are limited to 128 KB until a client has logged on.

### L8 - The server type flags were corrupted by restarts (Low, fixed)

Each start *added* the "NT server" flag to the server type instead of setting the bit, so the value announced on
the network changed with every restart.

### L9 - Null pointer in `SMBSrvSession.processPacket()` (Low, fixed)

After a packet had been processed and released, the code dereferenced the (now `null`) packet if a filesystem
transaction was active.

### L10 - `JavaNIOSearchContext.nextFileName()` could run off the end (Low, fixed)

The iterator was advanced without checking that another element exists.

### L11 - `ByteBufferPool` did not validate its arguments (Low, fixed)

The length check of the three configuration arrays used `&&` where `||` was meant.

### L12 - Extending a file with "set end of file" had no effect (Medium, fixed)

`FileChannel.truncate()` only ever shortens a file. A request to make a file longer was reported as successful and
ignored. Extending immediately would be the wrong fix: file copies usually start by setting the final size, and on
filesystems without sparse files (the FAT variants on SD cards) that can take minutes for a large file. The
requested size is now remembered and applied when the file is closed, if the file has not reached it by then.

### L13 - An open file was not told that it had been renamed (Low, fixed)

After a rename the open file object still pointed at the old path, so updating the modification time on close, or
opening the data channel late, failed.

### L14 - Garbage as the first message caused an exception with a stack trace (Low, fixed)

The error path of the negotiate handling threw while trying to build an error response for a message that was too
malformed to answer. The connection is now simply dropped.

### L15 - SMB1 buffer size followed the largest pooled buffer (Info, fixed)

SMB1 clients were offered the size of the largest buffer in the pool. With the new 1 MB buffers that would have
been far more than SMB1 length fields can carry, so the SMB1 value is capped at the size it had before.

## Left open

### A17 - The server is started and stopped on the main thread (Low)

Stopping waits for the server threads to finish, which can take up to about three seconds, during which the UI does
not react. Moving it to a background thread means reworking how the service tracks its state, which was not worth
the risk without being able to run the app on a device (see [verification.md](verification.md)).

### A18 - The server does not run when the phone is the Wi-Fi hotspot (Info)

Android does not report a hotspot as a network, so the service never sees an address to serve on. Supporting it
means enumerating the network interfaces directly.

### L16 - A NetBIOS keep-alive message is treated as a disconnect (Low)

When a keep-alive arrives on a NetBIOS session (port 139) on its own, the reader returns "no packet", which the
caller takes to mean that the client has closed the connection. This only affects clients that use the NetBIOS
transport instead of port 445, which in turn is only reachable on rooted devices. Fixing it means changing the
contract between the packet readers and the request handler for both transports.

## Things that were checked and are fine

* File names from clients cannot be used to leave the shared folder: `..` and absolute paths are rejected
  (`SMB2ParsingTest.pathsThatCouldEscapeTheShareAreRejected`).
* Every offset and length in an SMB2 request is checked against the size of the request before it is used.
* Signatures and authentication values are compared in constant time.
* The number of sessions and pending requests that one connection can create is bounded.
