# Improvements

What changed as a result of the review, by topic. The findings themselves, with their identifiers (`A1`, `L3`, …),
are in [../round-1.md](../round-1.md).

| Page | Topic |
| --- | --- |
| [smb2-smb3.md](smb2-smb3.md) | SMB2 and SMB3 support, the main new feature. |
| [not-rooted.md](not-rooted.md) | Does the app work on a phone that is not rooted? |
| [android-10-plus.md](android-10-plus.md) | Behaviour on Android 10 and later. |
| [app-fixes.md](app-fixes.md) | The other changes to the Android app. |
| [library-fixes.md](library-fixes.md) | Bugs fixed in the file server library. |
| [round-2.md](round-2.md) | The risk fixes of the second review round: memory limits, password guessing, signing, safe rename. |

## In one paragraph

The server now speaks SMB 2.0.2 to 3.1.1 with signing and encryption, so current versions of Windows, macOS, Linux
and Android file managers can connect without SMB1. A user name and password can be set, which is what makes
signing and encryption possible. The app now tells the truth about how to reach it on a phone without root, and no
longer blocks its UI talking to a root shell. A bug that could leave the start button dead after granting storage
access on Android 11+ is fixed, as are three bugs in the file server library that could corrupt data, make
overwriting large files fail, or leave the server unreachable after the network changed.

## What changed where

* `jfileserver/` - new. The JFileServer source, previously a binary dependency, with the SMB2/SMB3 implementation
  in `org.filesys.smb.server.smb2` and the fixes described in [library-fixes.md](library-fixes.md).
* `app/` - the fixes and new settings described in [app-fixes.md](app-fixes.md).
* `README.md`, store descriptions and change log - updated to match.
* `architecture/` and `code-review/` - new documentation.
