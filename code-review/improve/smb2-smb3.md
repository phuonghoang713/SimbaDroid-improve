# SMB2 and SMB3 support

## Why

The server only spoke SMB1, a protocol from the 1980s that current systems are busy removing: Windows has not
installed an SMB1 client by default since 2017, and macOS and most Android file managers prefer or require SMB2.
The README used to say "only SMBv1 is supported … c'est la vie".

## What was done

JFileServer's open source edition has the hooks for SMB2 (a parser factory, a protocol handler factory, the
dialect constants) but no implementation; that is part of the vendor's commercial edition. The implementation
here was written from the protocol specification ([MS-SMB2], [MS-NLMP], [MS-SPNG]) and plugs into those hooks.

To be able to change the library, its source was copied into this repository as the `jfileserver` module. It is
based on commit `660bf45` of <https://github.com/buttercookie42/jfileserver>, the fork that the app used before.
Parts that an Android file server has no use for (FTP, NFS, database backed filesystems, clustering, the XML
configuration and the stand-alone server application) were left out, which also removes the Hazelcast dependency.

## What is supported

| | |
| --- | --- |
| Dialects | SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1. The client and server agree on the highest one both support. |
| Upgrade from SMB1 | A client that starts with an SMB1 negotiate listing SMB2 dialects is switched to SMB2, as Windows expects. |
| Logon | NTLMv2, inside SPNEGO or bare. Guest and anonymous logons if no credentials are configured. |
| Signing | HMAC-SHA256 (SMB 2.x) and AES-CMAC (SMB 3.x), including the SMB 3.1.1 pre-authentication integrity check and "validate negotiate" for 3.0. |
| Encryption | AES-128-CCM and AES-128-GCM. Used if the client asks for it; can be made mandatory in the server configuration. |
| Large requests | Reads and writes of up to 1 MB per request (SMB 2.1 and later) instead of 64 KB. |
| Compounded requests | Yes, related and unrelated. Windows Explorer relies on these. |
| File operations | Create/open with all dispositions, read, write, flush, close, delete (delete-on-close and disposition), rename and move with or without replace, truncate/extend, timestamps. |
| Folder listing | All the information classes that clients use, wildcards, restart, listings that span several responses. |
| Information | File, filesystem and security information; free space; the classes that are not applicable return the proper "not supported" status. |
| Byte range locks | Shared and exclusive, enforced on reads and writes, released when the file is closed. |
| Share listing | The `IPC$` share and its `srvsvc`/`wkssvc` pipes, which is how clients get the list of shares. |
| Change notification | Requests are accepted and held until cancelled or the folder is closed. No notifications are generated (the app has change notification switched off). |

## What is not supported

These are deliberate omissions; none of them stops a client from working, clients fall back.

* Oplocks and leases (client side caching). Every open is granted without one.
* Durable and persistent handles, multichannel, DFS.
* Alternate data streams and extended attributes.
* Server side copy.
* Kerberos. Only NTLMv2 is offered, which is what clients use against a server that is not in a domain.
* AES-256 ciphers, AES-GMAC signing and compression (SMB 3.1.1 options).
* Lock requests that would have to wait are refused at once rather than queued.
* Windows permissions: every file reports "Everyone: full control". Access is decided by the share.

## New settings

SMB2/3 signing and encryption need a secret that both sides know, which is the password. The app therefore has a
small settings dialog:

* **User name and password.** If set, clients must log in with them, signing is required and encryption becomes
  available.
  If empty, anyone on the network can connect (as before), as a guest. Windows 11 24H2 and later refuse guest
  logons by default, so for those you need to set credentials.
* **Allow SMB1.** On by default, so that nothing that worked before stops working. Turn it off unless you have a
  device that needs it.

## Compatibility notes found during testing

* smbj signs its requests even on a guest session, with a key the server cannot know. Rejecting those would lock
  out every app built on smbj, so the server ignores signatures on sessions that have no key. Such a session is
  unauthenticated anyway.
* jcifs-ng refuses a guest session unless it is configured to accept one. That is the client's policy.

## Where the code is

`jfileserver/src/main/java/org/filesys/smb/server/smb2/`, about 7,400 lines including comments. The design is described in
[../../architecture/smb2.md](../../architecture/smb2.md).
