/*
 * Copyright (C) 2026 SimbaDroid contributors
 *
 * This file is part of JFileServer.
 *
 * JFileServer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * JFileServer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with JFileServer. If not, see <http://www.gnu.org/licenses/>.
 */

package org.filesys.smb.server.smb2;

import java.nio.charset.StandardCharsets;

import org.filesys.server.filesys.FileInfo;

/**
 * Packs file information into the structures used by the SMB2 create, close, query information and query
 * directory responses, see [MS-FSCC].
 */
final class SMB2InfoPacker {

    private static final int ALLOCATION_UNIT = 4096;

    // Attribute bits that are reported to clients
    private static final int ATTR_MASK = SMB2.ATTR_READONLY | SMB2.ATTR_HIDDEN | SMB2.ATTR_SYSTEM | SMB2.ATTR_DIRECTORY
            | SMB2.ATTR_ARCHIVE | SMB2.ATTR_NORMAL;

    // Sizes of the fixed parts of the directory information structures
    static final int DIR_INFO_FIXED = 64;
    static final int FULL_DIR_INFO_FIXED = 68;
    static final int BOTH_DIR_INFO_FIXED = 94;
    static final int NAMES_INFO_FIXED = 12;
    static final int ID_BOTH_DIR_INFO_FIXED = 104;
    static final int ID_FULL_DIR_INFO_FIXED = 80;

    private SMB2InfoPacker() {
    }

    /**
     * Return the file attributes to report for a file
     *
     * @param info FileInfo
     * @return int
     */
    static int attributes(FileInfo info) {
        int attr = info.getFileAttributes() & ATTR_MASK;

        if (info.isDirectory())
            attr = (attr | SMB2.ATTR_DIRECTORY) & ~SMB2.ATTR_NORMAL;
        else if ((attr & ~SMB2.ATTR_NORMAL) != 0)
            attr &= ~SMB2.ATTR_NORMAL;

        return attr == 0 ? SMB2.ATTR_NORMAL : attr;
    }

    static long endOfFile(FileInfo info) {
        return info.isDirectory() ? 0L : info.getSize();
    }

    static long allocationSize(FileInfo info) {
        if (info.isDirectory())
            return 0L;

        long size = info.getSize();
        long alloc = info.getAllocationSize();

        if (alloc < size)
            alloc = (size + ALLOCATION_UNIT - 1) & ~((long) ALLOCATION_UNIT - 1);
        return alloc;
    }

    static long creationTime(FileInfo info) {
        if (info.hasCreationDateTime())
            return SMB2ProtocolHandler.toNTTime(info.getCreationDateTime());
        return SMB2ProtocolHandler.toNTTime(info.getModifyDateTime());
    }

    static long accessTime(FileInfo info) {
        if (info.hasAccessDateTime())
            return SMB2ProtocolHandler.toNTTime(info.getAccessDateTime());
        return SMB2ProtocolHandler.toNTTime(info.getModifyDateTime());
    }

    static long writeTime(FileInfo info) {
        return SMB2ProtocolHandler.toNTTime(info.getModifyDateTime());
    }

    static long changeTime(FileInfo info) {
        if (info.hasChangeDateTime())
            return SMB2ProtocolHandler.toNTTime(info.getChangeDateTime());
        return SMB2ProtocolHandler.toNTTime(info.getModifyDateTime());
    }

    /**
     * Pack the creation, last access, last write and change times
     *
     * @param out  SMB2Buf
     * @param info FileInfo
     */
    static void packTimes(SMB2Buf out, FileInfo info) {
        out.putLong(creationTime(info));
        out.putLong(accessTime(info));
        out.putLong(writeTime(info));
        out.putLong(changeTime(info));
    }

    // FileBasicInformation, 40 bytes
    static void packBasic(SMB2Buf out, FileInfo info) {
        packTimes(out, info);
        out.putInt(attributes(info));
        out.putInt(0);
    }

    // FileStandardInformation, 24 bytes
    static void packStandard(SMB2Buf out, FileInfo info, boolean deletePending) {
        out.putLong(allocationSize(info));
        out.putLong(endOfFile(info));
        out.putInt(1);                          // number of links
        out.putByte(deletePending ? 1 : 0);
        out.putByte(info.isDirectory() ? 1 : 0);
        out.putShort(0);
    }

    // FileInternalInformation, 8 bytes
    static void packInternal(SMB2Buf out, FileInfo info) {
        out.putLong(info.getFileIdLong());
    }

    // FileNetworkOpenInformation, 56 bytes
    static void packNetworkOpen(SMB2Buf out, FileInfo info) {
        packTimes(out, info);
        out.putLong(allocationSize(info));
        out.putLong(endOfFile(info));
        out.putInt(attributes(info));
        out.putInt(0);
    }

    // FileNameInformation
    static void packName(SMB2Buf out, String path) {
        byte[] name = path.getBytes(StandardCharsets.UTF_16LE);
        out.putInt(name.length);
        out.putBytes(name);
    }

    // FileAllInformation
    static void packAll(SMB2Buf out, FileInfo info, boolean deletePending, int access, String path) {
        packBasic(out, info);
        packStandard(out, info, deletePending);
        packInternal(out, info);
        out.putInt(0);                          // EA size
        out.putInt(access);                     // access flags
        out.putLong(0);                         // current byte offset
        out.putInt(0);                          // mode
        out.putInt(0);                          // alignment requirement
        packName(out, path);
    }

    // FileStreamInformation, a file has just the default data stream
    static void packStreams(SMB2Buf out, FileInfo info) {
        if (info.isDirectory())
            return;

        byte[] name = "::$DATA".getBytes(StandardCharsets.UTF_16LE);
        out.putInt(0);                          // next entry offset
        out.putInt(name.length);
        out.putLong(endOfFile(info));
        out.putLong(allocationSize(info));
        out.putBytes(name);
    }

    /**
     * Return the size of the fixed part of a directory information structure
     *
     * @param infoClass int
     * @return int Size, or -1 if the information class is not supported
     */
    static int directoryInfoFixedLength(int infoClass) {
        switch (infoClass) {
            case SMB2.FILE_DIRECTORY_INFO:
                return DIR_INFO_FIXED;
            case SMB2.FILE_FULL_DIRECTORY_INFO:
                return FULL_DIR_INFO_FIXED;
            case SMB2.FILE_BOTH_DIRECTORY_INFO:
                return BOTH_DIR_INFO_FIXED;
            case SMB2.FILE_NAMES_INFO:
                return NAMES_INFO_FIXED;
            case SMB2.FILE_ID_BOTH_DIRECTORY_INFO:
                return ID_BOTH_DIR_INFO_FIXED;
            case SMB2.FILE_ID_FULL_DIRECTORY_INFO:
                return ID_FULL_DIR_INFO_FIXED;
            default:
                return -1;
        }
    }

    /**
     * Pack a directory entry, the next entry offset is left as zero
     *
     * @param out       SMB2Buf
     * @param infoClass int
     * @param info      FileInfo
     * @param name      byte[] UTF-16LE encoded file name
     */
    static void packDirectoryEntry(SMB2Buf out, int infoClass, FileInfo info, byte[] name) {
        out.putInt(0);                          // next entry offset
        out.putInt(0);                          // file index

        if (infoClass == SMB2.FILE_NAMES_INFO) {
            out.putInt(name.length);
            out.putBytes(name);
            return;
        }

        packTimes(out, info);
        out.putLong(endOfFile(info));
        out.putLong(allocationSize(info));
        out.putInt(attributes(info));
        out.putInt(name.length);

        switch (infoClass) {
            case SMB2.FILE_FULL_DIRECTORY_INFO:
                out.putInt(0);                  // EA size
                break;
            case SMB2.FILE_BOTH_DIRECTORY_INFO:
                out.putInt(0);                  // EA size
                out.putByte(0);                 // short name length
                out.putByte(0);
                out.putZeros(24);               // short name
                break;
            case SMB2.FILE_ID_BOTH_DIRECTORY_INFO:
                out.putInt(0);                  // EA size
                out.putByte(0);                 // short name length
                out.putByte(0);
                out.putZeros(24);               // short name
                out.putShort(0);
                out.putLong(info.getFileIdLong());
                break;
            case SMB2.FILE_ID_FULL_DIRECTORY_INFO:
                out.putInt(0);                  // EA size
                out.putInt(0);
                out.putLong(info.getFileIdLong());
                break;
            default:
                break;
        }

        out.putBytes(name);
    }

    /**
     * Pack a self-relative security descriptor that grants everyone full control. The underlying filesystem
     * does not have Windows style permissions, access is controlled by the share.
     *
     * @param out     SMB2Buf
     * @param secInfo int Security information flags from the request
     * @param isDir   boolean
     */
    static void packSecurityDescriptor(SMB2Buf out, int secInfo, boolean isDir) {

        // S-1-1-0, the Everyone group
        byte[] sid = {1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};

        boolean owner = (secInfo & SMB2.SECINFO_OWNER) != 0;
        boolean group = (secInfo & SMB2.SECINFO_GROUP) != 0;
        boolean dacl = (secInfo & SMB2.SECINFO_DACL) != 0;

        int start = out.position();

        out.putByte(1);                         // revision
        out.putByte(0);
        out.putShort(0x8000 | (dacl ? 0x0004 : 0));     // self relative, DACL present
        out.putInt(0);                          // owner offset
        out.putInt(0);                          // group offset
        out.putInt(0);                          // SACL offset
        out.putInt(0);                          // DACL offset

        if (owner) {
            out.setIntAt(start + 4, out.position() - start);
            out.putBytes(sid);
        }
        if (group) {
            out.setIntAt(start + 8, out.position() - start);
            out.putBytes(sid);
        }
        if (dacl) {
            out.setIntAt(start + 16, out.position() - start);

            int aceLen = 8 + sid.length;
            out.putByte(2);                     // ACL revision
            out.putByte(0);
            out.putShort(8 + aceLen);           // ACL size
            out.putShort(1);                    // ACE count
            out.putShort(0);

            out.putByte(0);                     // access allowed ACE
            out.putByte(isDir ? 0x03 : 0);      // object and container inherit
            out.putShort(aceLen);
            out.putInt(SMB2.ACC_FILE_ALL);
            out.putBytes(sid);
        }
    }
}
