# Android 10 and later

The app's `default` flavour supports Android 7 and later; this page is about what matters on Android 10+ (API 29
and up), which is what current phones run.

The app has **not been run on a device** as part of this work (see [../verification.md](../verification.md)), so
this page describes what the code does on each version and what was fixed, not test results from phones.

## Storage access

| Android version | How the app gets access to the storage |
| --- | --- |
| 10 (API 29) | The classic storage permission, with `requestLegacyExternalStorage` in the manifest. This gives full access to the shared storage and the SD card. |
| 11 and later (API 30+) | "All files access" (`MANAGE_EXTERNAL_STORAGE`), which the user grants on a system settings screen. |

Fixed:

* **A1** - on Android 11+ the app did not notice when the user came back from the settings screen, and the start
  button could stop working afterwards. This was the most serious problem for Android 11+ users.
* **A13** - the request could be left hanging on devices without that settings screen.

Unchanged, and worth knowing: since Android 11 no app can read `Android/data` and `Android/obb`, whatever
permissions it has. Clients will see these folders but find them empty or unreadable. Previously an unreadable
entry could cut a folder listing short (L6); now such entries are skipped and the rest of the folder is listed.

## Keeping the server running

The server runs in a foreground service with a notification, holding a wake lock.

Fixed:

* **A4** - the Wi-Fi lock used a mode that has done nothing since Android 10, so Wi-Fi could drop into power save
  mode when the screen went off. It now uses the high performance mode. A multicast lock was added so that the
  `simbadroid.local` name keeps resolving.
* **A15** - the manifest now declares what the "special use" foreground service is for, as Android 14 expects.
* **A5** - starting the foreground service can be refused since Android 12 when the app is in the background; this
  is now reported instead of crashing.

Not something the app can fix: some manufacturers stop background apps aggressively regardless of foreground
services. If the server stops after a while with the screen off, exempt the app from battery optimisation in the
system settings.

## Notifications

On Android 13+ the app asks for the notification permission when the server is started. If it is refused the
server still runs; the notification is just not shown.

## Network

* **A6** - the address is now taken from `onLinkPropertiesChanged()`. Reading it in `onAvailable()`, as before, is
  documented as unreliable, and on recent Android versions the address is often not there yet at that point.
* The app binds itself to the Wi-Fi (or Ethernet) network, so the server keeps working on a Wi-Fi network that has
  no internet access - a situation in which Android would otherwise prefer mobile data.

## Crypto performance

SMB2/SMB3 signs or encrypts every packet. On Android 10+ the platform's crypto provider is hardware accelerated;
the app used to override it with a pure Java one for all operations (**A7**). That override is gone, the Java
provider is now only used for the legacy algorithms that SMB1 needs.

## Build configuration

`compileSdk` is 36 and `targetSdk` 34, as before. Nothing in this change raises the minimum version.
