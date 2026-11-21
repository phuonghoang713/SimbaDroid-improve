# Review findings, round 2: risks

A second pass over the code, this time asking only one question: what can go wrong? That is, what could an
attacker on the network do, what could lose data, and what could crash. It covers the new SMB2/SMB3 code as
critically as the old code.

Identifiers start with `R2`. Fixes are summarised in [improve/round-2.md](improve/round-2.md).

## Fixed

### R2-1 - One packet could make the server run out of memory (High)

An SMB2 packet can contain many requests, and the responses to all of them were collected in memory before being
sent. A 50 KB packet with 400 read requests of 1 MB each would have made the server build a 400 MB response, which
is enough to crash the app. Any client that can connect could do this, including
a guest. This was a flaw in the SMB2 code added in round 1.

Fix: once the responses to one packet have reached the size of a single maximum response, the remaining requests
of that packet are answered with an error. Test: `SecurityTest.compoundResponsesAreLimited`.

### R2-2 - Passwords could be guessed without limit (Medium)

Neither the SMB1 nor the SMB2 logon limited failed attempts, so the password could be attacked at thousands of
guesses per second.

Fix: failed logons are counted per client address (`LogonThrottle`). After 20 failures further logons from that
address are refused for a minute. Counting per address means that an attacker cannot lock the real user out from
another machine, and the lockout is not extended by attempts made during it, so a mapped drive that keeps retrying
an old password does not stay locked out for ever. Tests: `LogonThrottleTest`, `SecurityTest`.

### R2-3 - Anonymous clients got a session even when a login is required (Medium)

With a password set, a client could still log on anonymously over SMB2/3. Such a session could only use `IPC$`, but
that is enough to list the shares, and it exposes the remote procedure call parsers to clients that have not
authenticated.

Fix: if guests are not allowed, anonymous SMB2/3 logons are refused.

### R2-4 - Signing was optional even with a login (Medium)

Unless the client insisted on it, messages were not signed, so somebody able to intercept the connection could
change them in transit.

Fix: when a user name and password are configured, the app now requires signing. Every SMB2/3 client supports it.
Guest connections cannot be signed (there is no shared secret), so this does not apply to them.

### R2-5 - Renaming over an existing file could lose that file (Medium)

"Rename and replace" deleted the existing file first and renamed afterwards. If the rename then failed, the old
file was gone and the new one was not in its place. Applications save documents exactly this way.

Fix: the existing file is moved aside, the rename is done, and only then is the old file deleted. If the rename
fails the old file is moved back.

### R2-6 - No limit on the number of connections (Medium)

A client could open connections until the app ran out of file handles or memory.

Fix: at most 200 connections are accepted at a time. Test: `SecurityTest.connectionsAreLimited`.

### R2-7 - Crash on devices without Wi-Fi hardware (Medium)

`SmbService.onCreate()` used the Wi-Fi manager without checking that there is one. There is none on devices that
only have Ethernet, such as some TV boxes, so the service crashed on start. A refused network request
(`requestNetwork()` can throw) crashed it too.

Fix: the Wi-Fi locks are optional, and if the network request is refused the service falls back to just watching
the networks.

### R2-8 - Byte range locks could be lost, and were unlimited (Low)

The lock table used a lock per file. Two threads locking and unlocking the last range of the same file at the same
moment could end up with separate lists, making a lock invisible to other clients. A client could also create an
unlimited number of lock entries.

Fix: one lock for the table, and at most 1024 locked ranges per file.

### R2-9 - A request racing with a close could reopen the file (Low)

The data channel of a file is opened on first use. A read that was already in progress when the same handle was
closed could open the channel again, and nothing would close it.

Fix: a file that has been closed refuses to open its channel again.

### R2-10 - The minimum password length was six characters (Low)

A login can be recorded by anybody on the same network and the password then attacked offline, which is a property
of the NTLM logon that every SMB server shares. The only defence is a password that is not short. The minimum is
now eight characters.

## Accepted, not changed

These are risks that remain. Each is a deliberate decision with the reason given.

### R2-A1 - The password is stored as plain text

It is in the app's private preferences, which other apps cannot read, and it is excluded from backups. Encrypting
it with a hardware backed key would protect it on a rooted or compromised phone only. It would also add a failure
mode that I cannot test without a device: if decryption failed, the app would either lose the password or, worse,
fall back to running without one. Not worth it without the means to test it.

### R2-A2 - SMB1 is weak, and still allowed by default

SMB1 logons use much weaker challenge-response schemes than SMB2/3, cannot be made tamper proof here, and allow
anonymous sessions on `IPC$`. SMB1 stays on by default only so that devices which worked before keep working.
**If you set a password, turn SMB1 off** unless you need it.

### R2-A3 - Other apps can start the server

`IntentReceiverActivity` is exported so that launcher shortcuts work with every launcher. Any app on the phone can
therefore send the "start server" intent. It cannot do so invisibly - the server shows a permanent notification -
and it cannot grant the storage permission.

### R2-A4 - Without a password the server is open

By design, and now stated in the app's status text. Anyone on the same network can read and change the files.

### R2-A5 - The connection limit is not applied on Android 6

The `oldApi` flavour uses the library's thread-per-connection code, which was not changed.

### R2-A6 - NTLM cannot protect against relay attacks, and Kerberos is not supported

Inherent to the logon method that is practical for a server that is not part of a domain.

## Checked again and found fine

* Path handling: the checks from round 1 hold, including for the target of a rename.
* Encryption: every message uses a fresh random nonce; decryption verifies the authentication tag before any
  data is used.
* Offsets and lengths: file offsets are 64 bit and checked for sign; byte range lock arithmetic is unsigned and
  cannot wrap.
* Sessions, pending requests and locks per connection are all bounded now.
