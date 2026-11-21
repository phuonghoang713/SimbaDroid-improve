# Changes to the Android app

Identifiers refer to [../round-1.md](../round-1.md). Two topics have their own pages:
[not-rooted.md](not-rooted.md) and [android-10-plus.md](android-10-plus.md).

## New

### Settings dialog

A *Settings* button on the main screen opens a dialog with

* user name and password (both empty = no login required), and
* a switch to allow SMB1.

The settings are stored in the app's private preferences (`server_settings`) and read when the server starts; if
the server is running the app says that a restart is needed. The password is stored as plain text, because both
the SMB1 and the SMB2 logon need the password itself or an equivalent of it. The file is private to the app and
excluded from backups (A14).

Files: `settings/ServerSettings.java`, `res/layout/dialog_settings.xml`, `MainActivity.java`.

### Status text

The text under the button now says

* how the server can be reached - with the port and an example if the standard port is not available, and
* who can connect: anyone, or the configured user.

The text can be selected and copied.

### Server configuration

`JLANFileServerConfiguration` now

* enables the SMB2 and SMB3 dialects, and SMB1 if allowed in the settings;
* creates the user account and requires a login if credentials are set;
* adds a pool of 1 MB buffers (allocated on demand) so that SMB 2.1+ clients can use large requests;
* reports the filesystem as NTFS (A16).

## Fixed

| Finding | File | Change |
| --- | --- | --- |
| A1 | `MainActivity`, `Permissions` | Use the request code to recognise the result of the "All files access" screen. |
| A2 | `SmbService`, `Iptables` | Port redirect is set up and removed on the background thread; `Iptables.iptables()` reports success. |
| A3 | `SmbService`, `MainActivity` | Advertise `_smb._tcp` with the reachable port; show the port. |
| A4 | `SmbService` | Wi-Fi lock in high performance mode; multicast lock; locks are not reference counted and only released if held. |
| A5 | `SmbService`, `JLANFileServerConfiguration` | Failures while starting are caught and reported with a toast. |
| A6 | `SmbService` | Track all connected local networks; follow address changes; restart the server on a new address. |
| A7 | `Application` | Bouncy Castle is added as the last crypto provider instead of the first. |
| A8 | `SmbService` | `onDestroy()` shuts the server down if it is still running. |
| A9 | `SmbService` | DNS-SD callbacks are handled on the main thread; stale callbacks are ignored. |
| A10 | `HostnameBroadcaster` | Restart when the address changes, not only when the name changes. |
| A11 | `MainActivity` | Refresh the button when the service connection is established or lost. |
| A12 | `SimbaDiskDriver` | A failure to restore the modification time no longer fails the rename; `StatFs` errors become `IOException`. |
| A13 | `PermissionsHelper`, `Permissions` | The "All files access" request is always resolved. |
| A14 | `res/xml/backup_rules.xml`, `data_extraction_rules.xml` | Exclude the settings file. |
| A15 | `AndroidManifest.xml` | Special use foreground service subtype; `ACCESS_WIFI_STATE` and `CHANGE_WIFI_MULTICAST_STATE` permissions for the locks. |

## Build

* The `jfileserver` dependency is now the module in this repository instead of a JitPack artifact, and the JitPack
  repository is only used for libsu. That also helps reproducible builds: one binary dependency less.
* `proguard-rules.pro` keeps the constructor of the SMB2 protocol handler, which is created by reflection.
* The version is `0.9a1` (version code 11), following the project's convention for development versions.

## Translations

The new texts were added in English, German and Italian, the three languages the app has. The German and Italian
texts were written by me and have not been checked by a native speaker.
