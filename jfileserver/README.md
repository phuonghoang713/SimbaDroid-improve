# JFileServer (SimbaDroid copy)

This directory contains the source of [JFileServer](https://github.com/FileSysOrg/jfileserver), a Java file
server, as used by SimbaDroid. It is licensed under the GNU Lesser General Public License, version 3 - see
[LICENSE](LICENSE). The original README is kept as [README.upstream.md](README.upstream.md).

## Origin

Based on commit `660bf45` of <https://github.com/buttercookie42/jfileserver>, which is a fork of the original
project with fixes for Android by the author of SimbaDroid.

## Modifications

As required by the licence, the changes made to the original are stated here.

* **Removed** the parts that SimbaDroid does not use: the packages `org.filesys.app`, `ftp`, `oncrpc` (except
  `AuthType`), `sample`, `debug.cluster`, `server.filesys.db`, `server.filesys.loader`,
  `server.filesys.cache.cluster`, `server.filesys.cache.hazelcast` and `util.db`, and the Maven build.
* **Added** an implementation of SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1 in the package
  `org.filesys.smb.server.smb2`. These files are new and carry their own copyright notice.
* **Changed** existing classes to connect that implementation (`DefaultParserFactory`, `ProtocolFactory`,
  `SMBSrvSession`, `SMBConfigSection`) and to fix bugs (`JavaNIONetworkFile`, `JavaNIODiskDriver`,
  `JavaNIOSearchContext`, `NIOSMBConnectionsHandler`, `ChannelPacketHandler`, `TcpipSMBChannelHandler`,
  `NetBIOSSMBChannelHandler`, `PacketHandler`, `SMBServer`, `SMBV1Parser`, `NetworkFile`, `ByteBufferPool`,
  `AuthType`).

The reasons for each change are in [../code-review/improve/library-fixes.md](../code-review/improve/library-fixes.md),
and the design of the SMB2/SMB3 code in [../architecture/smb2.md](../architecture/smb2.md).

## Building and testing

The module is a plain Java library without Android dependencies.

```
./gradlew :jfileserver:test
```

The tests start a server on a local port and exercise it with the smbj and jcifs-ng client libraries and with
hand-built protocol messages.
