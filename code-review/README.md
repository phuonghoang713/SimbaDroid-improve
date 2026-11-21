# Code review

This folder records the review of the SimbaDroid code base and what was done about it.

| File | Content |
| --- | --- |
| [round-1.md](round-1.md) | The findings of the review: every problem that was found, how serious it is and whether it has been fixed. |
| [verification.md](verification.md) | How the changes were tested, with the results - and, just as important, what could **not** be tested. |
| [improve/](improve/README.md) | What was changed as a result: one page per topic, written for someone who wants to know what is different now and why. |

The structure of the project itself is described in [../architecture](../architecture/README.md).

## Scope

Everything in the repository was read:

* the Android app in `app/` (about 2,700 lines of Java, plus resources, manifest and build files), and
* the parts of the JFileServer library that the app uses. Until now the library was pulled in as a binary from
  JitPack; its source is now part of this repository in `jfileserver/`, because adding SMB2/SMB3 meant changing it.

## Process

1. Read the app and the library, noting problems rather than fixing them straight away.
2. Vendor the library source and get it to build on its own, so that it can be run and tested on a desktop JVM
   without Android.
3. Implement SMB2/SMB3 in the library.
4. Test the server against two independent SMB client libraries and with hand-built protocol messages. This is
   where most of the library bugs were found - several of them are in code that was already there and also affect
   SMB1.
5. Fix the problems found in the app, add the settings that SMB2/SMB3 makes necessary and make the app behave
   sensibly on devices without root.
6. Build both flavours of the app, including the minified release build, and run Android lint.

## Summary of the findings

| Severity | Found | Fixed | Left open |
| --- | --- | --- | --- |
| High | 7 | 7 | 0 |
| Medium | 8 | 8 | 0 |
| Low | 14 | 12 | 2 |
| Informational | 5 | 4 | 1 |

The items that were left open are listed at the end of [round-1.md](round-1.md) together with the reason.
