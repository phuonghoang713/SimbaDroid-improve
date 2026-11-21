# Round 2: reducing risk

The fixes for the findings in [../round-2.md](../round-2.md).

| Finding | Where | Change |
| --- | --- | --- |
| R2-1 | `smb2/SMB2ProtocolHandler.runProtocol()` | Requests are refused once the responses to a packet exceed one maximum sized response. |
| R2-2 | new `server/auth/LogonThrottle`, used by `SMB2ProtocolHandler.handleSessionSetup()` and `LocalAuthenticator.authenticateUser()` | 20 failed logons per client address, then a one minute lockout. One throttle per server configuration (`SMBConfigSection.getLogonThrottle()`). |
| R2-3 | `SMB2ProtocolHandler.handleSessionSetup()` | Anonymous logons are refused unless guests are allowed. |
| R2-4 | `app/.../jlan/JLANFileServerConfiguration` | `setSMB2SigningRequired(true)` when credentials are configured. |
| R2-5 | `smb2/SMB2InfoOperations.renameFile()` | Move the replaced file aside, restore it if the rename fails. |
| R2-6 | `smb/server/nio/NIOSMBConnectionsHandler` | At most 200 connections. |
| R2-7 | `app/.../service/SmbService` | Wi-Fi and multicast locks are optional; network request failures are handled. |
| R2-8 | `smb2/SMB2LockManager` | Rewritten around a single lock; 1024 ranges per file. |
| R2-9 | `smb/server/disk/JavaNIONetworkFile` | No reopening after `closeFile()`. |
| R2-10 | `app/.../settings/ServerSettings` | Minimum password length 8. |

## What changes for users

* With a password set, clients must sign. All current clients do this automatically; nothing needs configuring.
* Passwords must have at least eight characters.
* After 20 wrong passwords in a row from one computer, that computer has to wait a minute.
* Anonymous connections are no longer possible once a password is set. Without a password nothing changes.

## Recommendations that the code cannot enforce

* Set a user name and password if the phone is ever on a network you do not control.
* Turn SMB1 off once a password is set, unless an old device needs it (R2-A2).
* Use a password that is not a dictionary word; it can be attacked offline by someone who records a login.

## Tests added

`LogonThrottleTest` (4 tests) and `SecurityTest` (6 tests): throttling, a few wrong passwords not locking the
user out, anonymous and unknown users refused, signing required, the compound response limit and the connection
limit. The suite now has 72 tests.
