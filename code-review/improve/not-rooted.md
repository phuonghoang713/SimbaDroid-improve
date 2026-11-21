# Does the app work on a phone that is **not rooted**?

Short answer: **yes, but clients have to connect to port 4450 instead of the standard SMB port.** Root was never
needed to run the server, only to make it reachable on the standard port. What has changed is that the server is now
useful without root (because modern clients can use it), and that the app says clearly which port to use.

## Where root is used

Only in one place: `SmbService` asks a root shell to add `iptables` rules that redirect the standard ports to the
ones the server listens on.

| Standard port | Redirected to | Used for |
| --- | --- | --- |
| TCP 445 | 4450 | SMB. This is the one that matters. |
| TCP 139 | 1139 | SMB over NetBIOS, used by very old clients. |
| UDP 137, 138 | 1137, 1138 | NetBIOS name lookup (`\\SIMBADROID`) and browsing. |

Android, like every Unix, only lets root open ports below 1024. Without root the rules cannot be added, the server
still runs, and it is reachable on port **4450**.

Nothing else needs root: reading and writing the storage uses the normal "All files access" permission.

## What was wrong for unrooted phones, and is fixed

* **A2** - the app ran the root shell commands on its main thread, which could freeze the UI even on phones where
  they could never succeed. They now run in the background.
* **A3** - the app announced itself on the network with port 445 and displayed addresses like `\\simbadroid`
  without mentioning a port. On an unrooted phone neither works. Now:
  * the status text shows the IP address, the port and an example such as `smb://192.168.1.20:4450/Internal`;
  * the network announcement (`_smb._tcp` via mDNS) carries the real port, so file managers that discover
    servers this way - Finder on macOS, Files on GNOME and KDE - connect to the right port by themselves.
* **L1** - with SMB1 only, the clients that *can* be pointed at another port mostly could not talk to the server
  anyway. With SMB2/SMB3 they can.

## How to connect to port 4450

Replace `192.168.1.20` with the address shown in the app. The share for the internal storage is called `Internal`,
the SD card (if there is one) `External`.

**Windows 11, version 24H2 or later**

```
net use Z: \\192.168.1.20\Internal /TCPPORT:4450
```

or in PowerShell: `New-SmbMapping -LocalPath Z: -RemotePath \\192.168.1.20\Internal -TcpPort 4450`.

Current Windows versions refuse guest logons and require signing by default, so set a user name and password in
the app's *Settings* first, and add `/user:<name>` to the command.

**Older Windows versions** cannot use another port for SMB. The only way is to set up a port forward on the Windows
machine itself; the project README links to a description of how to do that.

**macOS** - in Finder choose *Go → Connect to Server* and enter `smb://192.168.1.20:4450/Internal`. The phone
should also appear in the *Network* section of the Finder sidebar.

**Linux**

```
sudo mount -t cifs //192.168.1.20/Internal /mnt/phone -o port=4450,username=<name>
smbclient //192.168.1.20/Internal -p 4450 -U <name>
```

In GNOME Files or Dolphin enter `smb://192.168.1.20:4450/Internal`.

**Android and iOS file managers** - enter the address and set the port field to 4450.

## Known limits without root

* Names like `\\SIMBADROID` (NetBIOS) do not resolve, because the lookup uses UDP port 137. Use the IP address or
  `simbadroid.local`.
* Apps built on the jcifs-ng library can open a share on port 4450 but cannot *list* the shares: the library
  always uses port 445 for that. Type the share name (`Internal`) instead of browsing for it. This was found while
  testing and is a limitation of that library, not something the server can change.
* The server does not show up in the Windows *Network* folder.

## How this was checked

The root code path was reviewed, not executed: there was no Android device to run the app on (see
[../verification.md](../verification.md)). What was tested is the server itself on a non-standard port, which is
exactly the unrooted situation - every automated test connects to a port above 1024.
