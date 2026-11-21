# Verification

What was run to check the changes, what the results were, and what could not be checked.

## Not verified: the app on a real device

**The app has not been run on an Android device or emulator.** The machine this work was done on has no Android
device attached and cannot run an emulator (no hardware virtualisation). So for the Android part the evidence is:

* both flavours of the app compile and package (`assembleDefaultDebug`, `assembleOldApiDebug`),
* the minified release build succeeds and still contains the classes that are created by reflection,
* Android lint reports no errors, and
* the code was reviewed by reading it.

That is weaker than running it. The first thing to do with this change is to install the debug build on a phone
and go through the checklist at the end of this page.

Also not tested: real Windows, macOS and Linux kernel clients. The SMB server was tested with two SMB client
libraries instead (see below), which gives good coverage of the protocol but is not the same thing.

## The SMB server: automated tests

The library can run on a desktop JVM, so the server was tested there. The tests are in
`jfileserver/src/test/java/org/filesys/smb/server/smb2/` and run with

```
./gradlew :jfileserver:test
```

Each test starts a real server on a free local port, sharing a temporary folder, using the same configuration
that the app builds (minus the Android specific parts).

Result of the last run: **72 tests, 0 failures**.

| Test class | Tests | What it covers |
| --- | --- | --- |
| `SMB2CryptoTest` | 10 | AES-CMAC against the RFC 4493 test vectors; SMB 3.0 key derivation against the values published by Microsoft; signatures detect a changed byte, header field or key; AES-CCM and AES-GCM round trip and reject tampering with data, header or tag. |
| `SMB2ParsingTest` | 8 | Path validation (nothing can escape the share), range checks on request buffers, SPNEGO encode/decode including every possible truncation, NT hash against a known value, malformed NTLM messages. |
| `SmbjInteropTest` | 28 | A full set of file operations with the *smbj* client for each of the five dialects, as guest, anonymous, authenticated, with signing required, with encryption (SMB3 only) and against the thread-per-connection variant of the server. |
| `SmbjFeatureTest` | 4 | Overwriting large files, truncating and extending, delete-on-close, eight threads reading and writing one handle at once, byte range locks, change notification with cancel and close, Unicode and long file names, deep folders, listing the shares through the IPC$ pipe, two sessions on one connection. Run as guest, signed, encrypted and against the threaded server. |
| `JcifsInteropTest` | 6 | File operations with the *jcifs-ng* client for SMB1 and all SMB2/3 dialects, as guest and authenticated, with signing enforced. This is the regression test for SMB1. |
| `RawProtocolTest` | 4 | Hand-built messages: compounded requests (related and unrelated, including a failed create), upgrade from an SMB1 negotiate, about 20 error cases, and 1,500 randomly corrupted requests after which the server must still answer. |
| `ServerLifecycleTest` | 2 | Stopping and restarting the server 15 times in a row on the same port, and restarting with a client connected and a file open. |
| `SecurityTest` | 6 | Round 2: password guessing is throttled but a few mistakes do not lock the user out; anonymous and unknown users are refused when a login is required; a packet with 400 read requests gets a bounded response; connections over the limit are refused and the server recovers. |
| `LogonThrottleTest` | 4 | The throttle on its own: lockout, recovery, per client counting, bounded memory. |

Why two client libraries: they are independent implementations, so the server is not just being tested against my
own reading of the protocol. smbj and jcifs-ng are also what many Android file managers are built on.

### Bugs these tests found

* jcifs-ng and smbj behave differently for guest logons (smbj signs requests with a key the server cannot know).
  The server now ignores a signature it has no key to check on guest sessions.
* L2, L3 and L4 in [round-1.md](round-1.md) were all reproduced by a failing test before being fixed.
* An error raised after part of a response had been written sent a corrupt response.

### Fuzzing

A separate run sent 4,000 corrupted requests. The server kept running and stayed responsive. The only exceptions
logged came from the existing SMB1 code handling garbage as a first message; each of them just closed that one
connection (see L14).

## Throughput

Measured on the loopback interface of a virtual machine, with smbj as the client, 300 MB in 1 MB requests:

| Mode | Write | Read |
| --- | --- | --- |
| Guest (no signing) | 266 MB/s | 492 MB/s |
| Authenticated, signed (SMB 3.1.1) | 95 MB/s | 110 MB/s |
| Authenticated, encrypted (SMB 3.1.1) | 35 MB/s | 57 MB/s |

In the signed and encrypted cases the client library's own pure Java crypto is the limiting factor. These numbers
say nothing about a phone; they are here to show that the changes to the network code did not slow anything down
and that the server is well above Wi-Fi speeds.

## The app: builds

```
./gradlew :app:assembleDefaultDebug :app:assembleOldApiDebug :app:assembleDefaultRelease :app:lintDefaultDebug
```

* All three builds succeed.
* The release APK is minified by R8. It was checked that it still contains `SMB2ProtocolHandler` with its
  no-argument constructor (it is created by reflection) and the Bouncy Castle classes used directly.
* Lint: 0 errors. The remaining warnings were there before (newer dependency versions available, launcher icon
  details) apart from a few harmless ones about the wording of the new strings.

## Checklist for testing on a device

1. Install the debug build. Start the server; grant the notification and "All files access" permissions.
   The server should start as soon as you return from the settings screen (A1).
2. Without root: the status text shows the IP address and port 4450. Connect from another device using that port
   (see [improve/not-rooted.md](improve/not-rooted.md) for the commands) and copy a large file in each direction.
3. Open *Settings*, set a user name and password, restart the server and connect again with these credentials.
   Check that a wrong password is refused.
4. Turn the screen off during a copy; it should continue (A4).
5. Switch Wi-Fi off and on. The status should go to "waiting for network" and back, and the server should be
   reachable again (A6, L4).
6. Copy a file larger than 500 MB over an existing one of the same name (L3).
7. With root: confirm the superuser prompt; the status text should then show the `\\simbadroid` style addresses
   and the server should be reachable on port 445.
