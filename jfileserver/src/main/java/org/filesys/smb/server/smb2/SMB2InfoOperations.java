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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;

import org.filesys.server.filesys.DiskDeviceContext;
import org.filesys.server.filesys.DiskInterface;
import org.filesys.server.filesys.FileAttribute;
import org.filesys.server.filesys.FileInfo;
import org.filesys.server.filesys.FileStatus;
import org.filesys.server.filesys.NetworkFile;
import org.filesys.server.filesys.NotifyAction;
import org.filesys.server.filesys.SearchContext;
import org.filesys.server.filesys.SearchFlags;
import org.filesys.server.filesys.SrvDiskInfo;
import org.filesys.server.filesys.TreeConnection;
import org.filesys.server.filesys.VolumeInfo;
import org.filesys.smb.server.SMBSrvSession;
import org.filesys.util.WildCard;

/**
 * SMB2 information commands: query directory, query information and set information.
 */
final class SMB2InfoOperations {

    // Attributes to include in a directory search
    private static final int SEARCH_ATTRIBUTES = FileAttribute.Directory + FileAttribute.Hidden + FileAttribute.System;

    // Filesystem attribute flags
    private static final int FS_CASE_PRESERVED_NAMES = 0x00000002;
    private static final int FS_UNICODE_ON_DISK = 0x00000004;

    private static final int FS_DEVICE_DISK = 0x00000007;
    private static final int FS_DEVICE_IS_REMOTE = 0x00000010;
    private static final int FS_DEVICE_IS_MOUNTED = 0x00000020;

    private static final int MAX_COMPONENT_LENGTH = 255;
    private static final int SECTOR_SIZE = 512;

    private static final String DEFAULT_FILESYSTEM_NAME = "NTFS";

    // Suffix of the temporary name given to a file while it is being replaced by a rename
    private static final String REPLACED_SUFFIX = ".~replaced";

    // Special values for the timestamps in a set basic information request
    private static final long TIME_NO_CHANGE = 0L;
    private static final long TIME_DONT_UPDATE = -1L;
    private static final long TIME_RESUME_UPDATE = -2L;

    private final SMB2ProtocolHandler m_handler;

    SMB2InfoOperations(SMB2ProtocolHandler handler) {
        m_handler = handler;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Query directory
    //-------------------------------------------------------------------------------------------------------------

    int queryDirectory(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(33, 32);

        int infoClass = req.getByte(2);
        int flags = req.getByte(3);
        SMB2Open open = m_handler.findOpen(req, 8);
        int nameOff = req.getShort(24);
        int nameLen = req.getShort(26);
        int outLen = req.getInt(28);

        if (!open.isDirectory() || open.isPipe())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
        if (outLen < 0 || outLen > m_handler.maxIoSize())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        int fixedLen = SMB2InfoPacker.directoryInfoFixedLength(infoClass);
        if (fixedLen == -1)
            throw new SMB2Exception(SMB2.STATUS_INVALID_INFO_CLASS);

        String pattern = "*";
        if (nameLen > 0) {
            int namePos = req.checkRange(nameOff, nameLen);
            pattern = SMB2Buf.getUnicode(req.buffer(), namePos, nameLen & ~1);
        }

        // Response header, the output buffer follows
        out.putShort(9);
        out.putShort(SMB2.HEADER_LEN + 8);
        int lenPos = out.position();
        out.putInt(0);

        int dataStart = out.position();
        int count = 0;
        int lastEntry = -1;

        synchronized (open) {
            boolean restart = (flags & (SMB2.QD_RESTART_SCANS | SMB2.QD_REOPEN)) != 0;

            if (restart || !open.searchStarted)
                startSearch(open, pattern);

            while (true) {
                FileInfo info = nextEntry(open);
                if (info == null)
                    break;

                byte[] name = info.getFileName().getBytes(StandardCharsets.UTF_16LE);

                // Entries are aligned on 8 byte boundaries
                int entryStart = ((out.position() - dataStart) + 7) & ~7;

                if (entryStart + fixedLen + name.length > outLen) {

                    // The entry does not fit, return it in the next response
                    open.pendingInfo = info;

                    if (count == 0)
                        throw new SMB2Exception(SMB2.STATUS_INFO_LENGTH_MISMATCH);
                    break;
                }

                if (lastEntry != -1) {
                    out.align(dataStart, 8);
                    out.setIntAt(lastEntry, out.position() - lastEntry);
                }

                lastEntry = out.position();
                SMB2InfoPacker.packDirectoryEntry(out, infoClass, info, name);
                count++;

                if ((flags & SMB2.QD_RETURN_SINGLE_ENTRY) != 0)
                    break;
            }

            if (count == 0)
                throw new SMB2Exception(open.searchReturned ? SMB2.STATUS_NO_MORE_FILES : SMB2.STATUS_NO_SUCH_FILE);

            open.searchReturned = true;
        }

        out.setIntAt(lenPos, out.position() - dataStart);

        if (m_handler.hasDebug(SMBSrvSession.Dbg.SEARCH))
            m_handler.debug("Query directory " + open.getPath() + " pattern=" + pattern + " returned " + count);

        return SMB2.STATUS_SUCCESS;
    }

    /**
     * Start, or restart, the directory search for an open
     *
     * @param open    SMB2Open
     * @param pattern String
     * @exception Exception Error starting the search
     */
    private void startSearch(SMB2Open open, String pattern)
            throws Exception {

        open.closeSearch();
        open.searchStarted = true;
        open.searchReturned = false;

        // Convert the wildcard characters used by older clients
        if (WildCard.containsUnicodeWildcard(pattern))
            pattern = WildCard.convertUnicodeWildcardToDOS(pattern);

        boolean matchAll = pattern.equals("*") || pattern.equals("*.*");
        if (matchAll)
            pattern = "*";
        else if (pattern.indexOf('\\') != -1 || pattern.indexOf('/') != -1 || pattern.equals(".") || pattern.equals(".."))
            throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_INVALID);

        open.searchPattern = pattern;

        String dirPath = open.getPath();
        String searchPath = (dirPath.equals("\\") ? "" : dirPath) + "\\" + pattern;

        TreeConnection tree = open.getTree();
        DiskInterface disk = m_handler.diskInterface(tree);

        try {
            open.search = disk.startSearch(m_handler.sess(), tree, searchPath, SEARCH_ATTRIBUTES,
                    EnumSet.noneOf(SearchFlags.class));
        }
        catch (FileNotFoundException ex) {
            // No matching files
            open.search = null;
        }

        // A full listing starts with the entries for the directory itself and its parent
        open.dotEntries = matchAll ? 2 : 0;
    }

    /**
     * Return the next entry of the directory search
     *
     * @param open SMB2Open
     * @return FileInfo or null if there are no more entries
     * @exception Exception Error reading the directory
     */
    private FileInfo nextEntry(SMB2Open open)
            throws Exception {

        if (open.pendingInfo != null) {
            FileInfo info = open.pendingInfo;
            open.pendingInfo = null;
            return info;
        }

        if (open.dotEntries > 0) {
            String name = open.dotEntries == 2 ? "." : "..";
            open.dotEntries--;

            FileInfo info = m_handler.diskInterface(open.getTree()).getFileInformation(m_handler.sess(), open.getTree(),
                    open.getPath());
            if (info == null)
                info = new FileInfo(name, 0L, FileAttribute.Directory);

            info.setFileName(name);
            return info;
        }

        SearchContext search = open.search;
        if (search != null) {
            FileInfo info = new FileInfo();
            if (search.nextFileInfo(info) && info.getFileName() != null)
                return info;

            // The search is complete, release the directory resources now rather than waiting for the close
            open.closeSearch();
        }
        return null;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Query information
    //-------------------------------------------------------------------------------------------------------------

    int queryInfo(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(41, 40);

        int infoType = req.getByte(2);
        int infoClass = req.getByte(3);
        int outLen = req.getInt(4);
        int addInfo = req.getInt(16);
        SMB2Open open = m_handler.findOpen(req, 24);

        if (outLen < 0 || outLen > m_handler.maxIoSize())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        SMB2Buf data = new SMB2Buf(256);

        // Length of the fixed part of the information, a request buffer shorter than this is an error
        int fixedLen;

        switch (infoType) {
            case SMB2.INFO_FILE:
                fixedLen = queryFileInfo(open, infoClass, data);
                break;
            case SMB2.INFO_FILESYSTEM:
                fixedLen = queryFilesystemInfo(open, infoClass, data);
                break;
            case SMB2.INFO_SECURITY:
                SMB2InfoPacker.packSecurityDescriptor(data, addInfo, open.isDirectory());
                fixedLen = data.position();
                break;
            case SMB2.INFO_QUOTA:
                throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);
            default:
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
        }

        int dataLen = data.position();
        int status = SMB2.STATUS_SUCCESS;

        if (dataLen > outLen) {

            // A security descriptor cannot be truncated, tell the client the size that is required
            if (infoType == SMB2.INFO_SECURITY) {
                byte[] required = new byte[4];
                for (int i = 0; i < 4; i++)
                    required[i] = (byte) (dataLen >> (8 * i));
                throw new SMB2Exception(SMB2.STATUS_BUFFER_TOO_SMALL, required);
            }

            if (outLen < fixedLen)
                throw new SMB2Exception(SMB2.STATUS_INFO_LENGTH_MISMATCH);

            // Return as much of the variable length data as will fit
            dataLen = outLen;
            status = SMB2.STATUS_BUFFER_OVERFLOW;
        }

        out.putShort(9);
        out.putShort(SMB2.HEADER_LEN + 8);
        out.putInt(dataLen);
        if (dataLen > 0)
            out.putBytes(data.array(), 0, dataLen);
        else
            out.putByte(0);

        return status;
    }

    /**
     * Return the current details of an open file
     *
     * @param open SMB2Open
     * @return FileInfo
     * @exception Exception Error getting the file details
     */
    private FileInfo fileInfoFor(SMB2Open open)
            throws Exception {

        if (open.isPipe()) {
            FileInfo info = new FileInfo(open.getFile().getName(), 0L, SMB2.ATTR_NORMAL);
            info.setAllocationSize(4096);
            return info;
        }

        TreeConnection tree = open.getTree();
        FileInfo info = m_handler.diskInterface(tree).getFileInformation(m_handler.sess(), tree, open.getPath());

        if (info == null)
            throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_NOT_FOUND);

        // The client may have set a file size that has not been applied to the file yet
        long pendingSize = open.getFile().getPendingFileSize();
        if (pendingSize > info.getSize() && !info.isDirectory()) {
            info.setFileSize(pendingSize);
            info.setAllocationSize(0L);
        }
        return info;
    }

    /**
     * Pack file information
     *
     * @param open      SMB2Open
     * @param infoClass int
     * @param data      SMB2Buf
     * @return int Length of the fixed part of the information
     * @exception Exception Error getting the information
     */
    private int queryFileInfo(SMB2Open open, int infoClass, SMB2Buf data)
            throws Exception {

        FileInfo info = fileInfoFor(open);
        boolean deletePending = open.getFile().hasDeleteOnClose();

        switch (infoClass) {
            case SMB2.FILE_BASIC_INFO:
                SMB2InfoPacker.packBasic(data, info);
                break;
            case SMB2.FILE_STANDARD_INFO:
                SMB2InfoPacker.packStandard(data, info, deletePending);
                break;
            case SMB2.FILE_INTERNAL_INFO:
                SMB2InfoPacker.packInternal(data, info);
                break;
            case SMB2.FILE_EA_INFO:
                data.putInt(0);
                break;
            case SMB2.FILE_ACCESS_INFO:
                data.putInt(open.getAccess());
                break;
            case SMB2.FILE_POSITION_INFO:
                data.putLong(0);
                break;
            case SMB2.FILE_MODE_INFO:
                data.putInt(0);
                break;
            case SMB2.FILE_ALIGNMENT_INFO:
                data.putInt(0);
                break;
            case SMB2.FILE_NAME_INFO:
                SMB2InfoPacker.packName(data, open.getPath());
                return 4;
            case SMB2.FILE_ALL_INFO:
                SMB2InfoPacker.packAll(data, info, deletePending, open.getAccess(), open.getPath());
                return 100;
            case SMB2.FILE_STREAM_INFO:
                SMB2InfoPacker.packStreams(data, info);
                return Math.min(data.position(), 24);
            case SMB2.FILE_COMPRESSION_INFO:
                data.putLong(SMB2InfoPacker.endOfFile(info));
                data.putZeros(8);
                break;
            case SMB2.FILE_NETWORK_OPEN_INFO:
                SMB2InfoPacker.packNetworkOpen(data, info);
                break;
            case SMB2.FILE_ATTRIBUTE_TAG_INFO:
                data.putInt(SMB2InfoPacker.attributes(info));
                data.putInt(0);
                break;
            case SMB2.FILE_ALTERNATE_NAME_INFO:
                // Short file names are not generated
                throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_NOT_FOUND);
            case SMB2.FILE_FULL_EA_INFO:
                throw new SMB2Exception(SMB2.STATUS_EAS_NOT_SUPPORTED);
            case SMB2.FILE_NORMALIZED_NAME_INFO:
            case SMB2.FILE_ID_INFO:
                throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);
            default:
                throw new SMB2Exception(SMB2.STATUS_INVALID_INFO_CLASS);
        }

        return data.position();
    }

    /**
     * Pack filesystem information
     *
     * @param open      SMB2Open
     * @param infoClass int
     * @param data      SMB2Buf
     * @return int Length of the fixed part of the information
     * @exception Exception Error getting the information
     */
    private int queryFilesystemInfo(SMB2Open open, int infoClass, SMB2Buf data)
            throws Exception {

        TreeConnection tree = open.getTree();

        if (open.isPipe() || !(tree.getContext() instanceof DiskDeviceContext))
            throw new SMB2Exception(SMB2.STATUS_INVALID_DEVICE_REQUEST);

        DiskInterface disk = m_handler.diskInterface(tree);
        DiskDeviceContext diskCtx = (DiskDeviceContext) tree.getContext();

        switch (infoClass) {
            case SMB2.FS_VOLUME_INFO: {
                VolumeInfo volInfo = m_handler.volumeInformation(disk, diskCtx);

                String label = volInfo.getVolumeLabel();
                if (label == null || label.isEmpty())
                    label = tree.getSharedDevice().getName();
                byte[] labelByts = label.getBytes(StandardCharsets.UTF_16LE);

                long created = volInfo.hasCreationDateTime() ? volInfo.getCreationDateTime().getTime() : 0L;
                int serialNo = volInfo.hasSerialNumber() ? volInfo.getSerialNumber() : tree.getSharedDevice().getName().hashCode();

                data.putLong(SMB2ProtocolHandler.toNTTime(created));
                data.putInt(serialNo);
                data.putInt(labelByts.length);
                data.putByte(0);                // supports objects
                data.putByte(0);
                data.putBytes(labelByts);
                return 18;
            }

            case SMB2.FS_SIZE_INFO: {
                SrvDiskInfo diskInfo = m_handler.diskInformation(disk, diskCtx);

                data.putLong(diskInfo.getTotalUnits());
                data.putLong(diskInfo.getFreeUnits());
                data.putInt(diskInfo.getBlocksPerAllocationUnit());
                data.putInt(diskInfo.getBlockSize());
                break;
            }

            case SMB2.FS_FULL_SIZE_INFO: {
                SrvDiskInfo diskInfo = m_handler.diskInformation(disk, diskCtx);

                data.putLong(diskInfo.getTotalUnits());
                data.putLong(diskInfo.getFreeUnits());      // available to the caller
                data.putLong(diskInfo.getFreeUnits());      // actual free units
                data.putInt(diskInfo.getBlocksPerAllocationUnit());
                data.putInt(diskInfo.getBlockSize());
                break;
            }

            case SMB2.FS_DEVICE_INFO:
                data.putInt(FS_DEVICE_DISK);
                data.putInt(FS_DEVICE_IS_REMOTE | FS_DEVICE_IS_MOUNTED);
                break;

            case SMB2.FS_ATTRIBUTE_INFO: {
                String fsName = diskCtx.getFilesystemType();
                if (fsName == null || fsName.isEmpty())
                    fsName = DEFAULT_FILESYSTEM_NAME;
                byte[] fsNameByts = fsName.getBytes(StandardCharsets.UTF_16LE);

                data.putInt(FS_CASE_PRESERVED_NAMES | FS_UNICODE_ON_DISK);
                data.putInt(MAX_COMPONENT_LENGTH);
                data.putInt(fsNameByts.length);
                data.putBytes(fsNameByts);
                return 12;
            }

            case SMB2.FS_SECTOR_SIZE_INFO:
                data.putInt(SECTOR_SIZE);       // logical bytes per sector
                data.putInt(SECTOR_SIZE);       // physical bytes per sector for atomicity
                data.putInt(SECTOR_SIZE);       // physical bytes per sector for performance
                data.putInt(SECTOR_SIZE);       // effective physical bytes per sector for atomicity
                data.putInt(0);                 // flags
                data.putInt(0);                 // sector alignment offset
                data.putInt(0);                 // partition alignment offset
                break;

            case SMB2.FS_OBJECT_ID_INFO:
            case SMB2.FS_CONTROL_INFO:
                throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);

            default:
                throw new SMB2Exception(SMB2.STATUS_INVALID_INFO_CLASS);
        }

        return data.position();
    }

    //-------------------------------------------------------------------------------------------------------------
    // Set information
    //-------------------------------------------------------------------------------------------------------------

    int setInfo(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(33, 32);

        int infoType = req.getByte(2);
        int infoClass = req.getByte(3);
        int dataLen = req.getInt(4);
        int dataOff = req.getShort(8);
        SMB2Open open = m_handler.findOpen(req, 16);

        if (dataLen < 0 || dataLen > m_handler.maxIoSize())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        int dataPos = dataLen > 0 ? req.checkRange(dataOff, dataLen) : 0;

        switch (infoType) {
            case SMB2.INFO_FILE:
                if (open.isPipe())
                    break;
                setFileInfo(req, open, infoClass, dataPos, dataLen);
                break;
            case SMB2.INFO_SECURITY:
                // Permissions are controlled by the share, accept but ignore security descriptor changes
                if (!open.getTree().hasWriteAccess())
                    throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
                break;
            case SMB2.INFO_FILESYSTEM:
            case SMB2.INFO_QUOTA:
                throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);
            default:
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
        }

        out.putShort(2);
        return SMB2.STATUS_SUCCESS;
    }

    private void setFileInfo(SMB2Request req, SMB2Open open, int infoClass, int dataPos, int dataLen)
            throws Exception {

        byte[] buf = req.buffer();
        TreeConnection tree = open.getTree();
        NetworkFile netFile = open.getFile();
        SMBSrvSession sess = m_handler.sess();
        DiskInterface disk = m_handler.diskInterface(tree);

        switch (infoClass) {
            case SMB2.FILE_BASIC_INFO: {
                if (dataLen < 36)
                    throw new SMB2Exception(SMB2.STATUS_INFO_LENGTH_MISMATCH);

                long createTime = SMB2Buf.getLong(buf, dataPos);
                long accessTime = SMB2Buf.getLong(buf, dataPos + 8);
                long writeTime = SMB2Buf.getLong(buf, dataPos + 16);
                long changeTime = SMB2Buf.getLong(buf, dataPos + 24);
                int attrs = SMB2Buf.getInt(buf, dataPos + 32);

                FileInfo finfo = new FileInfo();
                int setFlags = 0;

                if (isTimeValue(createTime)) {
                    finfo.setCreationDateTime(SMB2ProtocolHandler.fromNTTime(createTime));
                    setFlags |= FileInfo.SetCreationDate;
                }
                if (isTimeValue(accessTime)) {
                    finfo.setAccessDateTime(SMB2ProtocolHandler.fromNTTime(accessTime));
                    setFlags |= FileInfo.SetAccessDate;
                }
                if (isTimeValue(writeTime)) {
                    finfo.setModifyDateTime(SMB2ProtocolHandler.fromNTTime(writeTime));
                    setFlags |= FileInfo.SetModifyDate;
                }
                if (isTimeValue(changeTime)) {
                    finfo.setChangeDateTime(SMB2ProtocolHandler.fromNTTime(changeTime));
                    setFlags |= FileInfo.SetChangeDate;
                }
                if (attrs != 0) {
                    finfo.setFileAttributes(attrs);
                    setFlags |= FileInfo.SetAttributes;
                }

                if (setFlags != 0) {
                    requireWritable(tree);

                    finfo.setFileInformationFlags(setFlags);
                    finfo.setNetworkFile(netFile);
                    disk.setFileInformation(sess, tree, open.getPath(), finfo);

                    SMB2FileOperations.notifyChange(tree, open.isDirectory(), NotifyAction.Modified, open.getPath());
                }
                break;
            }

            case SMB2.FILE_RENAME_INFO:
                renameFile(open, disk, buf, dataPos, dataLen);
                break;

            case SMB2.FILE_DISPOSITION_INFO: {
                if (dataLen < 1)
                    throw new SMB2Exception(SMB2.STATUS_INFO_LENGTH_MISMATCH);

                boolean delete = buf[dataPos] != 0;
                if (delete) {
                    requireWritable(tree);

                    if (open.getPath().equals("\\"))
                        throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
                    if (open.isDirectory() && !isDirectoryEmpty(open, disk))
                        throw new SMB2Exception(SMB2.STATUS_DIRECTORY_NOT_EMPTY);
                }
                netFile.setDeleteOnClose(delete);
                break;
            }

            case SMB2.FILE_END_OF_FILE_INFO: {
                if (dataLen < 8)
                    throw new SMB2Exception(SMB2.STATUS_INFO_LENGTH_MISMATCH);

                long size = SMB2Buf.getLong(buf, dataPos);
                if (size < 0 || open.isDirectory())
                    throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

                requireWriteAccess(open);
                disk.truncateFile(sess, tree, netFile, size);
                break;
            }

            case SMB2.FILE_ALLOCATION_INFO: {
                if (dataLen < 8)
                    throw new SMB2Exception(SMB2.STATUS_INFO_LENGTH_MISMATCH);

                long allocSize = SMB2Buf.getLong(buf, dataPos);
                if (allocSize < 0 || open.isDirectory())
                    throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

                requireWriteAccess(open);

                // Space is not pre-allocated, but an allocation smaller than the file truncates it
                FileInfo info = disk.getFileInformation(sess, tree, open.getPath());
                if (info != null && allocSize < info.getSize())
                    disk.truncateFile(sess, tree, netFile, allocSize);
                break;
            }

            case SMB2.FILE_POSITION_INFO:
            case SMB2.FILE_MODE_INFO:
            case SMB2.FILE_VALID_DATA_LENGTH_INFO:
                // Nothing to do
                break;

            case SMB2.FILE_FULL_EA_INFO:
                throw new SMB2Exception(SMB2.STATUS_EAS_NOT_SUPPORTED);

            case SMB2.FILE_LINK_INFO:
                throw new SMB2Exception(SMB2.STATUS_NOT_SUPPORTED);

            default:
                throw new SMB2Exception(SMB2.STATUS_INVALID_INFO_CLASS);
        }
    }

    private static boolean isTimeValue(long ntTime) {
        return ntTime != TIME_NO_CHANGE && ntTime != TIME_DONT_UPDATE && ntTime != TIME_RESUME_UPDATE;
    }

    private static void requireWritable(TreeConnection tree)
            throws SMB2Exception {
        if (!tree.hasWriteAccess())
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
    }

    private static void requireWriteAccess(SMB2Open open)
            throws SMB2Exception {
        requireWritable(open.getTree());
        if (!open.hasAccess(SMB2.ACC_WRITE_DATA | SMB2.ACC_APPEND_DATA))
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
    }

    /**
     * Check if a directory is empty
     *
     * @param open SMB2Open
     * @param disk DiskInterface
     * @return boolean
     * @exception Exception Error reading the directory
     */
    private boolean isDirectoryEmpty(SMB2Open open, DiskInterface disk)
            throws Exception {

        String dirPath = open.getPath();
        SearchContext search = null;

        try {
            search = disk.startSearch(m_handler.sess(), open.getTree(), (dirPath.equals("\\") ? "" : dirPath) + "\\*",
                    SEARCH_ATTRIBUTES, EnumSet.noneOf(SearchFlags.class));
            return search == null || !search.nextFileInfo(new FileInfo());
        }
        catch (FileNotFoundException ex) {
            return true;
        }
        finally {
            if (search != null)
                search.closeSearch();
        }
    }

    /**
     * Rename, or move, an open file or directory
     *
     * @param open    SMB2Open
     * @param disk    DiskInterface
     * @param buf     byte[]
     * @param dataPos int
     * @param dataLen int
     * @exception Exception Rename failed
     */
    private void renameFile(SMB2Open open, DiskInterface disk, byte[] buf, int dataPos, int dataLen)
            throws Exception {

        if (dataLen < 20)
            throw new SMB2Exception(SMB2.STATUS_INFO_LENGTH_MISMATCH);

        boolean replace = buf[dataPos] != 0;
        long rootDir = SMB2Buf.getLong(buf, dataPos + 8);
        int nameLen = SMB2Buf.getInt(buf, dataPos + 16);

        if (rootDir != 0 || nameLen <= 0 || nameLen > dataLen - 20)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        TreeConnection tree = open.getTree();
        SMBSrvSession sess = m_handler.sess();

        requireWritable(tree);

        String oldPath = open.getPath();
        String newPath = SMB2FileOperations.toSharePath(SMB2Buf.getUnicode(buf, dataPos + 20, nameLen & ~1));

        if (oldPath.equals("\\") || newPath.equals("\\"))
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
        if (newPath.equals(oldPath))
            return;

        // A directory cannot be moved into itself, or renamed whilst files within it are open
        if (open.isDirectory()) {
            if (newPath.regionMatches(true, 0, oldPath + "\\", 0, oldPath.length() + 1))
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
            if (m_handler.hasOpensBelow(tree, oldPath))
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
        }

        if (disk.fileExists(sess, tree, SMB2FileOperations.parentOf(newPath)) != FileStatus.DirectoryExists)
            throw new SMB2Exception(SMB2.STATUS_OBJECT_PATH_NOT_FOUND);

        // Check for an existing file with the new name, unless only the case of the name is being changed
        String replacedPath = null;

        if (!newPath.equalsIgnoreCase(oldPath)) {
            FileStatus targetSts = disk.fileExists(sess, tree, newPath);

            if (targetSts == FileStatus.FileExists || targetSts == FileStatus.DirectoryExists) {
                if (!replace)
                    throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_COLLISION);
                if (targetSts == FileStatus.DirectoryExists || open.isDirectory())
                    throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

                // Move the file that is being replaced out of the way rather than deleting it first, so that it
                // can be put back if the rename fails
                replacedPath = newPath + REPLACED_SUFFIX + Long.toHexString(System.nanoTime());

                try {
                    disk.renameFile(sess, tree, newPath, replacedPath, null);
                }
                catch (IOException ex) {
                    // Could not be moved aside, fall back to deleting it
                    replacedPath = null;
                    disk.deleteFile(sess, tree, newPath);
                }
            }
        }

        try {
            disk.renameFile(sess, tree, oldPath, newPath, open.getFile());
        }
        catch (IOException ex) {

            // Restore the file that was to be replaced
            if (replacedPath != null) {
                try {
                    disk.renameFile(sess, tree, replacedPath, newPath, null);
                }
                catch (IOException ex2) {
                    if (m_handler.hasDebug(SMBSrvSession.Dbg.ERROR))
                        m_handler.debug("Failed to restore " + newPath + " from " + replacedPath + ": " + ex2);
                }
            }

            int status = SMB2ProtocolHandler.mapException(ex);
            throw new SMB2Exception(status == SMB2.STATUS_UNSUCCESSFUL ? SMB2.STATUS_ACCESS_DENIED : status);
        }

        // The rename has been done, now the replaced file can go
        if (replacedPath != null) {
            try {
                disk.deleteFile(sess, tree, replacedPath);
            }
            catch (IOException ex) {
                if (m_handler.hasDebug(SMBSrvSession.Dbg.ERROR))
                    m_handler.debug("Failed to delete replaced file " + replacedPath + ": " + ex);
            }
        }

        open.setPath(newPath);
        open.getFile().setFullName(newPath);
        open.getFile().setName(SMB2FileOperations.nameOf(newPath));

        if (m_handler.hasDebug(SMBSrvSession.Dbg.FILE))
            m_handler.debug("Renamed " + oldPath + " to " + newPath);

        if (tree.getContext() instanceof DiskDeviceContext) {
            DiskDeviceContext diskCtx = (DiskDeviceContext) tree.getContext();
            if (diskCtx.hasFileServerNotifications())
                diskCtx.getChangeHandler().notifyRename(oldPath, newPath);
        }
    }
}
