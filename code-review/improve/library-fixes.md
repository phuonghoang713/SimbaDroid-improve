# Fixes in the file server library

All of these are in `jfileserver/`. Identifiers refer to [../round-1.md](../round-1.md). Except for L1 they are
bugs in code that was already there, and most of them affect SMB1 clients just as much as SMB2/3 clients.

| Finding | File | Change |
| --- | --- | --- |
| L2 | `smb/server/disk/JavaNIONetworkFile.java` | Reads and writes are positional and no longer depend on the shared file position. Opening and closing the channel is synchronised. |
| L3 | `JavaNIONetworkFile.java`, `JavaNIODiskDriver.java` | New `recreateFile()`, used after a large file has been moved to the trashcan. |
| L4 | `smb/server/nio/NIOSMBConnectionsHandler.java` | `stopHandler()` waits (up to 2.5 s) for the thread that owns the listening sockets. |
| L5 | `smb/server/nio/ChannelPacketHandler.java`, `TcpipSMBChannelHandler.java`, `NetBIOSSMBChannelHandler.java` | New `readFully()`; reads and writes wait instead of spinning, and time out after 60 s without progress. |
| L6 | `smb/server/disk/JavaNIOSearchContext.java` | One attribute read per entry; entries that cannot be read are skipped. |
| L7 | `smb/server/PacketHandler.java` and the two channel handlers | Maximum request size, 128 KB until the SMB2 handler raises it after a logon. |
| L8 | `smb/server/SMBServer.java` | Set the NT server flag with a bitwise OR instead of adding it. |
| L9 | `smb/server/SMBSrvSession.java` | Null check. |
| L10 | `JavaNIOSearchContext.java` | Check `hasNext()`. |
| L11 | `server/memory/ByteBufferPool.java` | Logical OR instead of AND in the argument check. |
| L12 | `JavaNIONetworkFile.java`, `server/filesys/NetworkFile.java` | Extending a file is deferred to the close; the pending size is reported to the client in the meantime. |
| L13 | `JavaNIONetworkFile.java`, `JavaNIODiskDriver.java` | New `updatePath()`, called after a rename. |
| L14 | `SMBSrvSession.java` | Drop the connection if no error response can be built. |
| L15 | `smb/server/SMBV1Parser.java` | Cap the SMB1 buffer size. |

## Changes that connect SMB2 to the existing code

| File | Change |
| --- | --- |
| `smb/server/DefaultParserFactory.java` | Creates the SMB2 parser; all dialects are supported. |
| `smb/server/ProtocolFactory.java` | Registers the SMB2 protocol handler for the SMB2 and SMB3 dialects. |
| `smb/server/SMBSrvSession.java` | Accepts the SMB2 "wildcard" dialect from an SMB1 negotiate if any SMB2/3 dialect is enabled, and does not count the session as opened until the real negotiate has happened. |
| `smb/server/SMBConfigSection.java` | New options: require signing, offer encryption, require encryption. |
| `oncrpc/AuthType.java` | Kept on its own, without the NFS code it used to sit next to. |

## Removed from the vendored copy

`org.filesys.app`, `ftp`, `oncrpc` (except `AuthType`), `sample`, `debug.cluster`, `server.filesys.db`,
`server.filesys.loader`, `server.filesys.cache.cluster`, `server.filesys.cache.hazelcast` and `util.db`.
None of it was reachable from the app.
