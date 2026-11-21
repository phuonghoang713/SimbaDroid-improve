# SimbaDroid

![App logo](app/src/main/res/mipmap-mdpi/ic_launcher.png)

SimbaDroid is an SMB server for Android, allowing you to access the contents of your storage (both
internal storage or an external SD card) from your computer via wi-fi.

## Download

<a href="https://f-droid.org/packages/de.buttercookie.simbadroid">
<img src="https://f-droid.org/badge/get-it-on.png" width="230" alt="Get it on F-Droid" >
</a><br>
&nbsp;&nbsp;&nbsp; <a href="https://apt.izzysoft.de/fdroid/index/apk/de.buttercookie.simbadroid">
<img src="https://gitlab.com/IzzyOnDroid/repo/-/raw/master/assets/IzzyOnDroidButton.png" width="200" alt="Get it on IzzyOnDroid">
</a>

… or download it directly from the [Github Releases page](https://github.com/buttercookie42/SimbaDroid/releases).

## Notes

The downloads above are the releases of the original project. The changes described below (SMB2/SMB3, the
settings, the fixes) are newer than those releases; to get them, build the app from this repository.

### Protocol versions

SimbaDroid supports **SMB2 and SMB3** (dialects 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1), including message signing and
AES encryption, and the old **SMB1** protocol for devices that cannot do anything else. Client and server agree on
the newest version both support. SMB1 can be switched off in the settings, which is recommended if you do not need
it.

### Root is optional

As on all Unixoid operating systems, an app cannot open a port < 1024 without root, and the default SMB port is 445.

* **With root**, SimbaDroid redirects the standard ports to its own, and the phone is reachable like any other
  file server: `\\simbadroid.local`, `\\simbadroid` or `\\<ip address>`.
* **Without root**, the server is reachable on port **4450**, so you need an SMB client that lets you specify the
  port. The app shows the address and port to use.

Connecting to port 4450 (replace the address with the one shown in the app):

| Client | How |
| --- | --- |
| Windows 11 24H2 or later | `net use Z: \\192.168.1.20\Internal /TCPPORT:4450`<br>or `New-SmbMapping -LocalPath "Z:" -RemotePath "\\192.168.1.20\Internal" -TcpPort 4450` |
| Older Windows versions | Not possible directly. You need some kind of [port mapping setup](https://serverfault.com/questions/1011395/access-smb-over-a-custom-port/1065212#1065212) to allow Windows to transparently connect to port 4450. |
| macOS | Finder → Go → Connect to Server → `smb://192.168.1.20:4450/Internal` |
| Linux | `mount -t cifs //192.168.1.20/Internal /mnt/phone -o port=4450`, `smbclient //192.168.1.20/Internal -p 4450`, or `smb://192.168.1.20:4450/Internal` in the file manager |
| Android / iOS file managers | Enter the address and set the port to 4450 |

The server also announces itself via mDNS (`_smb._tcp`) with the correct port, so it may simply show up in the
network view of macOS and Linux file managers.

### Shares and access

Shares for the internal storage (*"Internal"*) as well as an external SD card (*"External"* – if one is detected)
are set up automatically.

By default they are accessible **without authentication**, so be careful about using this app in public networks.
In the *Settings* you can set a user name and password. Clients then have to log in, and can sign and encrypt the
connection. Current Windows versions (Windows 11 24H2 and later) no longer connect to servers without a login
unless you relax their security settings, so for those you will want to set credentials.

`READ/WRITE/MANAGE_EXTERNAL_STORAGE` is required for filesystem access.

### Limitations

* The server does not run while the phone itself is the Wi-Fi hotspot.
* Without root, NetBIOS names (`\\simbadroid`) do not resolve; use the IP address or `simbadroid.local`.
* Not supported: oplocks/leases, durable handles, multichannel, DFS, alternate data streams, Kerberos.
* Folder change notifications are accepted but never sent, so an open Explorer window does not refresh by itself
  when files change on the phone.

## Compatibility

SimbaDroid should run on Android 6 and newer. The original author tested Android 6 and 14. The SMB2/SMB3 support
and the other recent changes have been tested with automated tests of the server on a desktop JVM, but **not yet
on an Android device** – see [code-review/verification.md](code-review/verification.md).

## Building

```
./gradlew :jfileserver:test          # tests of the file server
./gradlew :app:assembleDefaultDebug  # the app for Android 7+
./gradlew :app:assembleOldApiDebug   # the app for Android 6
```

You need a JDK 17 or later (a full JDK, including `jlink`) and the Android SDK with platform 36.

## Documentation

* [architecture/](architecture/README.md) – how the app and the server are put together.
* [code-review/](code-review/README.md) – the findings of a review of the code, how the changes were verified, and
  in [code-review/improve/](code-review/improve/README.md) what was improved.

## Licenses

SimbaDroid is © Jan Henning, 2024 and is mostly provided under the Mozilla Public License 2.0
(see LICENSE.md)

Portions of the code are provided under the Apache License, Version 2.0 (see apache-2.0.txt)

"[Lion](https://thenounproject.com/icon/lion-6029941/)" icon used in the logo by Gabriel Baudon
from [the Noun Project](https://thenounproject.com/)  under the
[CC BY 3.0 license](https://creativecommons.org/licenses/by/3.0/).

_JFileServer_ is used under the LGPL-3.0 license (see lgpl-3.0.md and gpl-3.0.md). Its source code is
included in this repository in the `jfileserver` directory. It is based on
[this fork](https://github.com/buttercookie42/jfileserver) of the
[original project](https://github.com/FileSysOrg/jfileserver) and has been modified: unused parts were
removed, bugs were fixed and SMB2/SMB3 support was added. The modifications are licensed under the
LGPL-3.0 as well; see `jfileserver/README.md` for details.

_libsu_, _JmDNS_, _Apache Commons Lang_, _Guava_, _Gson_, _JNA_ and the _Android Support Library_ are
used under the Apache License, Version 2.0

The tests of the file server additionally use _JUnit_ (Eclipse Public License 1.0), _smbj_ (Apache
License, Version 2.0) and _jcifs-ng_ (LGPL-2.1). These are not part of the app.

_SLF4J_ is used under the **MIT license**:

Copyright (c) 2004-2022 QOS.ch Sarl (Switzerland)
All rights reserved.

Permission is hereby granted, free  of charge, to any person obtaining
a  copy  of this  software  and  associated  documentation files  (the
"Software"), to  deal in  the Software without  restriction, including
without limitation  the rights to  use, copy, modify,  merge, publish,
distribute,  sublicense, and/or sell  copies of  the Software,  and to
permit persons to whom the Software  is furnished to do so, subject to
the following conditions:

The  above  copyright  notice  and  this permission  notice  shall  be
included in all copies or substantial portions of the Software.

THE  SOFTWARE IS  PROVIDED  "AS  IS", WITHOUT  WARRANTY  OF ANY  KIND,
EXPRESS OR  IMPLIED, INCLUDING  BUT NOT LIMITED  TO THE  WARRANTIES OF
MERCHANTABILITY,    FITNESS    FOR    A   PARTICULAR    PURPOSE    AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE,  ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

_Bouncy Castle_ is used under the following license:

**Bouncy Castle License**

Copyright (c) 2000 - 2024 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

### Notices
#### JmDNS

Java Multicast Domain Name Server (JmDNS)

This project was originally developed by Arthur van Hoff under the GNU
Lesser General Public License as jRendevous.  It was moved to Sourceforge
by Rick Blair and renamed to JmDNS with the Arthur's kind permission.
It has been re-released under the Apache License, Version 2.0.
In 2014, it has been moved from Sourceforge to Github by Kai Kreuzer
with the kind approval from Arthur and Rick.

Details of the Apache License, Version 2.0 can be found at:
http://www.apache.org/licenses/

#### Apache Commons Lang

Apache Commons Lang

Copyright 2001-2024 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (https://www.apache.org/).