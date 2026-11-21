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

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.filesys.server.core.ShareType;
import org.filesys.server.filesys.AccessDeniedException;
import org.filesys.server.filesys.CreateDisposition;
import org.filesys.server.filesys.DiskDeviceContext;
import org.filesys.server.filesys.DiskInterface;
import org.filesys.server.filesys.FileInfo;
import org.filesys.server.filesys.FileOpenParams;
import org.filesys.server.filesys.FileStatus;
import org.filesys.server.filesys.NetworkFile;
import org.filesys.server.filesys.NotifyAction;
import org.filesys.server.filesys.TooManyFilesException;
import org.filesys.server.filesys.TreeConnection;
import org.filesys.smb.ImpersonationLevel;
import org.filesys.smb.SharingMode;
import org.filesys.smb.WinNT;
import org.filesys.smb.server.SMBSrvSession;

/**
 * SMB2 file commands: create, close, flush, read, write and lock.
 */
final class SMB2FileOperations {

    private static final String INVALID_NAME_CHARS = "\"*/<>?|:";

    private static final String DATA_STREAM_SUFFIX = "::$DATA";

    // Create context names
    private static final int CTX_MAXIMAL_ACCESS = tag("MxAc");
    private static final int CTX_QUERY_ON_DISK_ID = tag("QFid");
    private static final int CTX_TIMEWARP = tag("TWrp");

    private static final int CTX_HEADER_LEN = 16;
    private static final int MAX_CREATE_CONTEXTS = 32;

    // Sizes of the fixed parts of the responses
    private static final int CREATE_RESPONSE_FIXED = 88;
    private static final int READ_RESPONSE_FIXED = 16;

    private static final int LOCK_ELEMENT_LEN = 24;
    private static final int MAX_LOCKS = 64;

    private static final long APPEND_OFFSET = 0xFFFFFFFFFFFFFFFFL;

    private final SMB2ProtocolHandler m_handler;

    SMB2FileOperations(SMB2ProtocolHandler handler) {
        m_handler = handler;
    }

    private static int tag(String name) {
        byte[] byts = name.getBytes(StandardCharsets.US_ASCII);
        return SMB2Buf.getInt(byts, 0);
    }

    /**
     * Convert a file name from a request to a share relative path, validating it on the way. The returned path
     * always starts with a backslash, the root of the share is a single backslash.
     *
     * @param name String
     * @return String
     * @exception SMB2Exception Invalid name
     */
    static String toSharePath(String name)
            throws SMB2Exception {

        int start = 0;
        int end = name.length();

        while (start < end && name.charAt(start) == '\\')
            start++;
        while (end > start && name.charAt(end - 1) == '\\')
            end--;

        if (start == end)
            return "\\";

        // Validate each path component, relative components are not allowed as they could be used to step
        // outside of the share
        int compStart = start;

        for (int i = start; i <= end; i++) {
            char ch = i < end ? name.charAt(i) : '\\';

            if (ch == '\\') {
                int compLen = i - compStart;
                if (compLen == 0 || (compLen == 1 && name.charAt(compStart) == '.')
                        || (compLen == 2 && name.charAt(compStart) == '.' && name.charAt(compStart + 1) == '.'))
                    throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_INVALID);
                compStart = i + 1;
            }
            else if (ch < 0x20 || INVALID_NAME_CHARS.indexOf(ch) != -1)
                throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_INVALID);
        }

        return "\\" + name.substring(start, end);
    }

    /**
     * Return the parent folder of a share relative path
     *
     * @param path String
     * @return String
     */
    static String parentOf(String path) {
        int idx = path.lastIndexOf('\\');
        return idx <= 0 ? "\\" : path.substring(0, idx);
    }

    /**
     * Return the file name part of a share relative path
     *
     * @param path String
     * @return String
     */
    static String nameOf(String path) {
        return path.substring(path.lastIndexOf('\\') + 1);
    }

    /**
     * Expand the generic and maximum allowed bits of an access mask into specific access rights
     *
     * @param desired  int
     * @param writable boolean true if the share is writable
     * @return int
     */
    private static int expandAccess(int desired, boolean writable) {
        int access = desired & ~(SMB2.ACC_GENERIC_ALL | SMB2.ACC_GENERIC_READ | SMB2.ACC_GENERIC_WRITE
                | SMB2.ACC_GENERIC_EXECUTE | SMB2.ACC_MAXIMUM_ALLOWED);

        if ((desired & SMB2.ACC_GENERIC_ALL) != 0)
            access |= SMB2.ACC_FILE_ALL;
        if ((desired & SMB2.ACC_GENERIC_READ) != 0)
            access |= 0x00120089;
        if ((desired & SMB2.ACC_GENERIC_WRITE) != 0)
            access |= 0x00120116;
        if ((desired & SMB2.ACC_GENERIC_EXECUTE) != 0)
            access |= 0x001200A0;
        if ((desired & SMB2.ACC_MAXIMUM_ALLOWED) != 0)
            access |= writable ? SMB2.ACC_FILE_ALL : SMB2.ACC_FILE_READ_ONLY;

        return access;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Create
    //-------------------------------------------------------------------------------------------------------------

    int create(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(57, 56);

        int impersonation = req.getInt(4);
        int desiredAccess = req.getInt(24);
        int fileAttrs = req.getInt(28);
        int shareAccess = req.getInt(32);
        int disposition = req.getInt(36);
        int options = req.getInt(40);
        int nameOff = req.getShort(44);
        int nameLen = req.getShort(46);
        int ctxOff = req.getInt(48);
        int ctxLen = req.getInt(52);

        byte[] buf = req.buffer();
        String name = "";

        if (nameLen > 0) {
            int namePos = req.checkRange(nameOff, nameLen);
            name = SMB2Buf.getUnicode(buf, namePos, nameLen & ~1);
        }

        TreeConnection tree = req.tree;
        SMBSrvSession sess = m_handler.sess();
        int hdrPos = out.position() - SMB2.HEADER_LEN;

        // Named pipes on the IPC$ share
        ShareType shareType = tree.getSharedDevice().getType();
        if (shareType == ShareType.ADMINPIPE || shareType == ShareType.NAMEDPIPE)
            return m_handler.ioctlOperations().createPipe(req, out, name);

        DiskInterface disk = m_handler.diskInterface(tree);

        if (!tree.hasReadAccess())
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

        if (disposition < SMB2.DISP_SUPERSEDE || disposition > SMB2.DISP_OVERWRITE_IF)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        boolean wantDirectory = (options & SMB2.OPT_DIRECTORY_FILE) != 0;
        boolean wantFile = (options & SMB2.OPT_NON_DIRECTORY_FILE) != 0;

        if (wantDirectory && wantFile)
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        // Named streams are not supported, but allow the default data stream to be named explicitly
        int streamPos = name.indexOf(':');
        if (streamPos != -1) {
            if (!name.regionMatches(true, streamPos, DATA_STREAM_SUFFIX, 0, name.length() - streamPos)
                    || name.length() - streamPos != DATA_STREAM_SUFFIX.length())
                throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_INVALID);
            name = name.substring(0, streamPos);
        }

        String path = toSharePath(name);

        // Parse the create contexts
        int[] contexts = parseCreateContexts(req, ctxOff, ctxLen);

        // Previous versions of files are not available
        if (hasContext(contexts, CTX_TIMEWARP))
            throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_NOT_FOUND);

        // Work out the access being requested
        boolean writable = tree.hasWriteAccess();
        int explicitAccess = expandAccess(desiredAccess & ~SMB2.ACC_MAXIMUM_ALLOWED, writable);
        int access = expandAccess(desiredAccess, writable);
        boolean maxAllowed = (desiredAccess & SMB2.ACC_MAXIMUM_ALLOWED) != 0;

        if (access == 0)
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

        boolean deleteOnClose = (options & SMB2.OPT_DELETE_ON_CLOSE) != 0;

        if (!writable && ((explicitAccess & SMB2.ACC_WRITE_MASK) != 0 || deleteOnClose))
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

        // The root of the share cannot be deleted
        if (deleteOnClose && path.equals("\\"))
            throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

        // Check the current state of the path
        FileStatus fileSts = disk.fileExists(sess, tree, path);
        boolean exists = fileSts == FileStatus.FileExists || fileSts == FileStatus.DirectoryExists;
        boolean isDirectory = fileSts == FileStatus.DirectoryExists;

        boolean overwrite = disposition == SMB2.DISP_SUPERSEDE || disposition == SMB2.DISP_OVERWRITE
                || disposition == SMB2.DISP_OVERWRITE_IF;

        NetworkFile netFile = null;
        int action;

        if (!exists) {
            boolean parentExists = disk.fileExists(sess, tree, parentOf(path)) == FileStatus.DirectoryExists;

            if (disposition == SMB2.DISP_OPEN || disposition == SMB2.DISP_OVERWRITE || !parentExists)
                throw new SMB2Exception(parentExists ? SMB2.STATUS_OBJECT_NAME_NOT_FOUND : SMB2.STATUS_OBJECT_PATH_NOT_FOUND);

            if (!writable)
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

            isDirectory = wantDirectory;

            // New files are always opened for read/write access
            FileOpenParams params = openParams(req, path, disposition, access | SMB2.ACC_READ_DATA | SMB2.ACC_WRITE_DATA,
                    fileAttrs, shareAccess, options, impersonation);

            if (isDirectory) {
                disk.createDirectory(sess, tree, params);
                netFile = disk.openFile(sess, tree, params);
            }
            else
                netFile = disk.createFile(sess, tree, params);

            action = SMB2.CREATE_ACTION_CREATED;
        }
        else {
            if (disposition == SMB2.DISP_CREATE)
                throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_COLLISION);
            if (isDirectory && wantFile)
                throw new SMB2Exception(SMB2.STATUS_FILE_IS_A_DIRECTORY);
            if (!isDirectory && wantDirectory)
                throw new SMB2Exception(SMB2.STATUS_NOT_A_DIRECTORY);
            if (isDirectory && overwrite)
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
            if (overwrite && !writable)
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

            if (isDirectory)
                options |= WinNT.CreateDirectory;

            // The driver opens the file for read/write or read-only access depending on the data access bits
            boolean needWrite = overwrite || (explicitAccess & (SMB2.ACC_WRITE_DATA | SMB2.ACC_APPEND_DATA)) != 0;
            boolean tryWrite = needWrite || (maxAllowed && writable && !isDirectory);

            int driverAccess = (access | SMB2.ACC_READ_DATA) & ~SMB2.ACC_WRITE_DATA;
            if (tryWrite)
                driverAccess |= SMB2.ACC_WRITE_DATA;

            try {
                netFile = disk.openFile(sess, tree, openParams(req, path, disposition, driverAccess, fileAttrs, shareAccess,
                        options, impersonation));
            }
            catch (AccessDeniedException ex) {

                // Write access was only requested via maximum allowed, fall back to opening the file read-only
                if (needWrite)
                    throw ex;

                access &= ~SMB2.ACC_WRITE_MASK;
                driverAccess &= ~SMB2.ACC_WRITE_DATA;

                netFile = disk.openFile(sess, tree, openParams(req, path, disposition, driverAccess, fileAttrs, shareAccess,
                        options, impersonation));
            }

            if (overwrite) {
                try {
                    disk.truncateFile(sess, tree, netFile, 0L);
                }
                catch (IOException ex) {
                    closeQuietly(disk, tree, netFile);
                    throw ex;
                }
                action = disposition == SMB2.DISP_SUPERSEDE ? SMB2.CREATE_ACTION_SUPERSEDED : SMB2.CREATE_ACTION_OVERWRITTEN;
            }
            else
                action = SMB2.CREATE_ACTION_OPENED;
        }

        if (netFile == null)
            throw new SMB2Exception(SMB2.STATUS_OBJECT_NAME_NOT_FOUND);

        if (deleteOnClose)
            netFile.setDeleteOnClose(true);

        // Allocate a file handle
        int handle;
        try {
            handle = tree.addFile(netFile, sess);
        }
        catch (TooManyFilesException ex) {
            netFile.setDeleteOnClose(false);
            closeQuietly(disk, tree, netFile);
            throw new SMB2Exception(SMB2.STATUS_TOO_MANY_OPENED_FILES);
        }

        SMB2Open open = m_handler.addOpen(req, netFile, handle, path, access, isDirectory, false);

        if (m_handler.hasDebug(SMBSrvSession.Dbg.FILE))
            m_handler.debug("Create " + open + " action=" + action + " access=0x" + Integer.toHexString(access));

        // Get the file details for the response. The file is open at this point, so do not fail the request if
        // the details cannot be read.
        FileInfo info = null;
        try {
            info = disk.getFileInformation(sess, tree, path);
        }
        catch (IOException ex) {
            // Use the details from the open file
        }

        if (info == null)
            info = infoFromFile(netFile, isDirectory);

        writeCreateResponse(out, hdrPos, action, info, open.getFileId(), contexts, access);

        if (action == SMB2.CREATE_ACTION_CREATED)
            notifyChange(tree, isDirectory, NotifyAction.Added, path);

        return SMB2.STATUS_SUCCESS;
    }

    private FileOpenParams openParams(SMB2Request req, String path, int disposition, int access, int fileAttrs,
                                      int shareAccess, int options, int impersonation) {
        FileOpenParams params = new FileOpenParams(path, CreateDisposition.fromInt(disposition), access, fileAttrs,
                SharingMode.fromInt(shareAccess & 0x07), 0L, options, 0, ImpersonationLevel.fromInt(impersonation), 0,
                req.processId());

        params.setTreeId(req.treeId);
        params.setSession(m_handler.sess());
        return params;
    }

    /**
     * Build file information from an open file, used if the driver cannot return details for the path
     *
     * @param netFile     NetworkFile
     * @param isDirectory boolean
     * @return FileInfo
     */
    static FileInfo infoFromFile(NetworkFile netFile, boolean isDirectory) {
        FileInfo info = new FileInfo(netFile.getName(), isDirectory ? 0L : netFile.getFileSize(),
                isDirectory ? SMB2.ATTR_DIRECTORY : netFile.getFileAttributes());

        if (netFile.hasModifyDate()) {
            info.setModifyDateTime(netFile.getModifyDate());
            info.setChangeDateTime(netFile.getModifyDate());
        }
        if (netFile.hasCreationDate())
            info.setCreationDateTime(netFile.getCreationDate());
        if (netFile.hasAccessDate())
            info.setAccessDateTime(netFile.getAccessDate());
        return info;
    }

    /**
     * Parse the create contexts of a request, returning the names of the contexts as integer tags
     *
     * @param req    SMB2Request
     * @param ctxOff int
     * @param ctxLen int
     * @return int[]
     * @exception SMB2Exception Invalid context list
     */
    private static int[] parseCreateContexts(SMB2Request req, int ctxOff, int ctxLen)
            throws SMB2Exception {

        if (ctxLen == 0)
            return new int[0];

        byte[] buf = req.buffer();
        int pos = req.checkRange(ctxOff, ctxLen);
        int end = pos + ctxLen;

        int[] tags = new int[MAX_CREATE_CONTEXTS];
        int count = 0;

        while (count < MAX_CREATE_CONTEXTS) {
            if (pos + CTX_HEADER_LEN > end)
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

            int next = SMB2Buf.getInt(buf, pos);
            int nameOff = SMB2Buf.getShort(buf, pos + 4);
            int nameLen = SMB2Buf.getShort(buf, pos + 6);

            if (nameOff + nameLen > end - pos)
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

            // Only contexts with four character names are of interest
            tags[count++] = nameLen == 4 ? SMB2Buf.getInt(buf, pos + nameOff) : 0;

            if (next == 0)
                break;
            if (next < CTX_HEADER_LEN || next > end - pos)
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
            pos += next;
        }

        int[] result = new int[count];
        System.arraycopy(tags, 0, result, 0, count);
        return result;
    }

    private static boolean hasContext(int[] contexts, int tag) {
        for (int ctx : contexts) {
            if (ctx == tag)
                return true;
        }
        return false;
    }

    /**
     * Write a create response
     *
     * @param out      SMB2Buf
     * @param hdrPos   int Position of the response header
     * @param action   int
     * @param info     FileInfo
     * @param fileId   long
     * @param contexts int[] Create contexts from the request
     * @param access   int Granted access
     */
    static void writeCreateResponse(SMB2Buf out, int hdrPos, int action, FileInfo info, long fileId, int[] contexts,
                                    int access) {
        out.putShort(89);
        out.putByte(SMB2.OPLOCK_NONE);
        out.putByte(0);
        out.putInt(action);
        SMB2InfoPacker.packTimes(out, info);
        out.putLong(SMB2InfoPacker.allocationSize(info));
        out.putLong(SMB2InfoPacker.endOfFile(info));
        out.putInt(SMB2InfoPacker.attributes(info));
        out.putInt(0);
        out.putLong(fileId);
        out.putLong(fileId);

        int ctxFieldsPos = out.position();
        out.putInt(0);
        out.putInt(0);

        boolean maxAccess = hasContext(contexts, CTX_MAXIMAL_ACCESS);
        boolean diskId = hasContext(contexts, CTX_QUERY_ON_DISK_ID);

        if (!maxAccess && !diskId) {
            out.putByte(0);
            return;
        }

        int ctxStart = out.position();
        int lastCtx = -1;

        if (maxAccess) {
            lastCtx = startCreateContext(out, lastCtx, CTX_MAXIMAL_ACCESS, 8);
            out.putInt(SMB2.STATUS_SUCCESS);
            out.putInt(access);
        }

        if (diskId) {
            lastCtx = startCreateContext(out, lastCtx, CTX_QUERY_ON_DISK_ID, 32);
            out.putLong(info.getFileIdLong());
            out.putLong(0);
            out.putZeros(16);
        }

        out.setIntAt(ctxFieldsPos, ctxStart - hdrPos);
        out.setIntAt(ctxFieldsPos + 4, out.position() - ctxStart);
    }

    /**
     * Write the header of a create context, chaining it to the previous context
     *
     * @param out     SMB2Buf
     * @param prevCtx int Position of the previous context, or -1
     * @param tag     int
     * @param dataLen int
     * @return int Position of the context
     */
    private static int startCreateContext(SMB2Buf out, int prevCtx, int tag, int dataLen) {
        if (prevCtx != -1) {
            out.align(prevCtx, 8);
            out.setIntAt(prevCtx, out.position() - prevCtx);
        }

        int pos = out.position();
        out.putInt(0);              // next
        out.putShort(16);           // name offset
        out.putShort(4);            // name length
        out.putShort(0);
        out.putShort(24);           // data offset
        out.putInt(dataLen);
        out.putInt(tag);
        out.putInt(0);
        return pos;
    }

    private void closeQuietly(DiskInterface disk, TreeConnection tree, NetworkFile netFile) {
        try {
            disk.closeFile(m_handler.sess(), tree, netFile);
        }
        catch (Exception ex) {
            // Ignore, the open is being abandoned
        }
    }

    /**
     * Pass a change on to the filesystem change notification handler, if one is enabled for the share
     *
     * @param tree      TreeConnection
     * @param directory boolean
     * @param action    NotifyAction
     * @param path      String
     */
    static void notifyChange(TreeConnection tree, boolean directory, NotifyAction action, String path) {
        if (tree.getContext() instanceof DiskDeviceContext) {
            DiskDeviceContext diskCtx = (DiskDeviceContext) tree.getContext();
            if (diskCtx.hasFileServerNotifications()) {
                if (directory)
                    diskCtx.getChangeHandler().notifyDirectoryChanged(action, path);
                else
                    diskCtx.getChangeHandler().notifyFileChanged(action, path);
            }
        }
    }

    //-------------------------------------------------------------------------------------------------------------
    // Close
    //-------------------------------------------------------------------------------------------------------------

    int close(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(24, 24);

        int flags = req.getShort(2);
        SMB2Open open = m_handler.findOpen(req, 8);

        TreeConnection tree = open.getTree();
        NetworkFile netFile = open.getFile();
        SMBSrvSession sess = m_handler.sess();

        m_handler.removeOpen(open);

        FileInfo info = null;
        IOException closeError = null;

        if (open.isPipe()) {
            tree.removeFile(open.getHandle(), sess);
            netFile.setClosed(true);
        }
        else {
            DiskInterface disk = m_handler.diskInterface(tree);
            boolean deleted = netFile.hasDeleteOnClose();
            boolean modified = netFile.getWriteCount() > 0;

            try {
                disk.closeFile(sess, tree, netFile);
            }
            catch (IOException ex) {
                closeError = ex;
            }
            finally {
                netFile.setClosed(true);
                tree.removeFile(open.getHandle(), sess);
            }

            if (m_handler.hasDebug(SMBSrvSession.Dbg.FILE))
                m_handler.debug("Close " + open + (deleted ? " deleted" : ""));

            if (closeError == null) {
                if (deleted)
                    notifyChange(tree, open.isDirectory(), NotifyAction.Removed, open.getPath());
                else if (modified)
                    notifyChange(tree, false, NotifyAction.Modified, open.getPath());

                if ((flags & SMB2.CLOSE_POSTQUERY_ATTRIB) != 0 && !deleted)
                    info = disk.getFileInformation(sess, tree, open.getPath());
            }
        }

        // The handle has been released, but report a failure to flush or delete the file
        if (closeError != null)
            throw closeError;

        out.putShort(60);
        out.putShort(info != null ? SMB2.CLOSE_POSTQUERY_ATTRIB : 0);
        out.putInt(0);

        if (info != null) {
            SMB2InfoPacker.packTimes(out, info);
            out.putLong(SMB2InfoPacker.allocationSize(info));
            out.putLong(SMB2InfoPacker.endOfFile(info));
            out.putInt(SMB2InfoPacker.attributes(info));
        }
        else
            out.putZeros(52);

        return SMB2.STATUS_SUCCESS;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Flush
    //-------------------------------------------------------------------------------------------------------------

    int flush(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(24, 24);

        SMB2Open open = m_handler.findOpen(req, 8);

        if (!open.isPipe() && !open.isDirectory())
            m_handler.diskInterface(open.getTree()).flushFile(m_handler.sess(), open.getTree(), open.getFile());

        out.putShort(4);
        out.putShort(0);
        return SMB2.STATUS_SUCCESS;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Read
    //-------------------------------------------------------------------------------------------------------------

    int read(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(49, 48);

        int length = req.getInt(4);
        long offset = req.getLong(8);
        SMB2Open open = m_handler.findOpen(req, 16);
        int minCount = req.getInt(32);

        if (length < 0 || length > m_handler.maxIoSize())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        out.putShort(17);
        out.putByte(SMB2.HEADER_LEN + READ_RESPONSE_FIXED);
        out.putByte(0);
        int lenPos = out.position();
        out.putInt(0);              // data length
        out.putInt(0);              // data remaining
        out.putInt(0);

        int dataPos = out.position();
        int total = 0;
        int status = SMB2.STATUS_SUCCESS;

        if (open.isPipe()) {
            boolean[] moreData = new boolean[1];
            byte[] data = m_handler.ioctlOperations().pipeRead(open, length, moreData);

            out.putBytes(data);
            total = data.length;

            if (moreData[0])
                status = SMB2.STATUS_BUFFER_OVERFLOW;
        }
        else {
            if (open.isDirectory())
                throw new SMB2Exception(SMB2.STATUS_INVALID_DEVICE_REQUEST);
            if (!open.hasAccess(SMB2.ACC_READ_DATA | SMB2.ACC_EXECUTE))
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);
            if (offset < 0)
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
            if (SMB2LockManager.hasLocks() && !SMB2LockManager.canAccess(open, offset, length, false))
                throw new SMB2Exception(SMB2.STATUS_FILE_LOCK_CONFLICT);

            DiskInterface disk = m_handler.diskInterface(open.getTree());
            SMBSrvSession sess = m_handler.sess();

            // Read directly into the response buffer
            out.ensureAvailable(length);
            byte[] buf = out.array();

            while (total < length) {
                int rdLen = disk.readFile(sess, open.getTree(), open.getFile(), buf, dataPos + total, length - total,
                        offset + total);
                if (rdLen <= 0)
                    break;
                total += rdLen;
            }

            if ((total == 0 && length > 0) || total < minCount)
                throw new SMB2Exception(SMB2.STATUS_END_OF_FILE);

            out.position(dataPos + total);
        }

        out.setIntAt(lenPos, total);
        if (total == 0)
            out.putByte(0);

        return status;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Write
    //-------------------------------------------------------------------------------------------------------------

    int write(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(49, 48);

        int dataOff = req.getShort(2);
        int length = req.getInt(4);
        long offset = req.getLong(8);
        SMB2Open open = m_handler.findOpen(req, 16);

        if (length < 0 || length > m_handler.maxIoSize())
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

        int dataPos = length > 0 ? req.checkRange(dataOff, length) : 0;

        if (open.isPipe())
            m_handler.ioctlOperations().pipeWrite(open, req.buffer(), dataPos, length);
        else {
            if (open.isDirectory())
                throw new SMB2Exception(SMB2.STATUS_INVALID_DEVICE_REQUEST);
            if (!open.getTree().hasWriteAccess() || !open.hasAccess(SMB2.ACC_WRITE_DATA | SMB2.ACC_APPEND_DATA))
                throw new SMB2Exception(SMB2.STATUS_ACCESS_DENIED);

            // An offset of -1 writes at the end of the file
            if (offset == APPEND_OFFSET) {
                FileInfo info = m_handler.diskInterface(open.getTree()).getFileInformation(m_handler.sess(), open.getTree(),
                        open.getPath());
                offset = info != null ? info.getSize() : open.getFile().getFileSize();
            }
            else if (offset < 0)
                throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);

            if (SMB2LockManager.hasLocks() && !SMB2LockManager.canAccess(open, offset, length, true))
                throw new SMB2Exception(SMB2.STATUS_FILE_LOCK_CONFLICT);

            if (length > 0)
                m_handler.diskInterface(open.getTree()).writeFile(m_handler.sess(), open.getTree(), open.getFile(),
                        req.buffer(), dataPos, length, offset);
        }

        out.putShort(17);
        out.putShort(0);
        out.putInt(length);         // count
        out.putInt(0);              // remaining
        out.putShort(0);            // write channel info offset
        out.putShort(0);            // write channel info length
        out.putByte(0);

        return SMB2.STATUS_SUCCESS;
    }

    //-------------------------------------------------------------------------------------------------------------
    // Lock
    //-------------------------------------------------------------------------------------------------------------

    int lock(SMB2Request req, SMB2Buf out)
            throws Exception {

        req.checkBody(48, 48);

        int lockCnt = req.getShort(2);
        SMB2Open open = m_handler.findOpen(req, 8);

        if (lockCnt < 1 || lockCnt > MAX_LOCKS || req.bodyLength() < 24 + (lockCnt * LOCK_ELEMENT_LEN))
            throw new SMB2Exception(SMB2.STATUS_INVALID_PARAMETER);
        if (open.isPipe() || open.isDirectory())
            throw new SMB2Exception(SMB2.STATUS_INVALID_DEVICE_REQUEST);

        boolean unlock = (req.getInt(24 + 16) & SMB2.LOCK_UNLOCK) != 0;
        int acquired = 0;
        int status = SMB2.STATUS_SUCCESS;

        for (int i = 0; i < lockCnt && status == SMB2.STATUS_SUCCESS; i++) {
            int pos = 24 + (i * LOCK_ELEMENT_LEN);
            long offset = req.getLong(pos);
            long length = req.getLong(pos + 8);
            int flags = req.getInt(pos + 16);

            // Lock and unlock requests cannot be mixed
            if (((flags & SMB2.LOCK_UNLOCK) != 0) != unlock)
                status = SMB2.STATUS_INVALID_PARAMETER;
            else if (unlock) {
                if (!SMB2LockManager.unlock(open, offset, length))
                    status = SMB2.STATUS_RANGE_NOT_LOCKED;
            }
            else if ((flags & (SMB2.LOCK_SHARED | SMB2.LOCK_EXCLUSIVE)) == 0)
                status = SMB2.STATUS_INVALID_PARAMETER;
            else if (SMB2LockManager.lock(open, offset, length, (flags & SMB2.LOCK_EXCLUSIVE) != 0))
                acquired++;
            else
                status = SMB2.STATUS_LOCK_NOT_GRANTED;
        }

        if (status != SMB2.STATUS_SUCCESS) {

            // Release any locks that were taken by the failed request
            for (int i = 0; i < acquired; i++) {
                int pos = 24 + (i * LOCK_ELEMENT_LEN);
                SMB2LockManager.unlock(open, req.getLong(pos), req.getLong(pos + 8));
            }
            throw new SMB2Exception(status);
        }

        out.putShort(4);
        out.putShort(0);
        return SMB2.STATUS_SUCCESS;
    }
}
