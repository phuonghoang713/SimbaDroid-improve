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

import org.filesys.server.filesys.FileInfo;
import org.filesys.server.filesys.NetworkFile;
import org.filesys.server.filesys.SearchContext;
import org.filesys.server.filesys.TreeConnection;

/**
 * An open file, directory or named pipe on an SMB2 session.
 */
public final class SMB2Open {

    private final long m_fileId;
    private final SMB2Session m_session;
    private final int m_treeId;
    private final TreeConnection m_tree;
    private final NetworkFile m_file;
    private final int m_handle;
    private final int m_access;
    private final boolean m_directory;
    private final boolean m_pipe;

    // Share relative path, starting with a backslash
    private volatile String m_path;

    // Directory enumeration state
    SearchContext search;
    String searchPattern;
    FileInfo pendingInfo;
    int dotEntries;
    boolean searchStarted;

    // Outstanding change notification request
    volatile SMB2ProtocolHandler.PendingRequest pendingNotify;

    // Byte range locks are held on this open
    volatile boolean hasLocks;
    volatile String lockKey;

    // Entries have been returned by the current directory search
    boolean searchReturned;

    volatile boolean closed;

    SMB2Open(long fileId, SMB2Session session, int treeId, TreeConnection tree, NetworkFile file, int handle, String path,
             int access, boolean directory, boolean pipe) {
        m_fileId = fileId;
        m_session = session;
        m_treeId = treeId;
        m_tree = tree;
        m_file = file;
        m_handle = handle;
        m_path = path;
        m_access = access;
        m_directory = directory;
        m_pipe = pipe;
    }

    public long getFileId() {
        return m_fileId;
    }

    public SMB2Session getSession() {
        return m_session;
    }

    public int getTreeId() {
        return m_treeId;
    }

    public TreeConnection getTree() {
        return m_tree;
    }

    public NetworkFile getFile() {
        return m_file;
    }

    /**
     * Return the file handle allocated by the tree connection
     *
     * @return int
     */
    public int getHandle() {
        return m_handle;
    }

    public String getPath() {
        return m_path;
    }

    void setPath(String path) {
        m_path = path;
    }

    public int getAccess() {
        return m_access;
    }

    public boolean hasAccess(int mask) {
        return (m_access & mask) != 0;
    }

    public boolean isDirectory() {
        return m_directory;
    }

    public boolean isPipe() {
        return m_pipe;
    }

    /**
     * Release the directory search, if one is active
     */
    synchronized void closeSearch() {
        if (search != null) {
            try {
                search.closeSearch();
            }
            catch (Exception ex) {
                // Ignore, the search is being discarded
            }
            search = null;
        }
        pendingInfo = null;
        dotEntries = 0;
    }

    @Override
    public String toString() {
        return "[SMB2 open 0x" + Long.toHexString(m_fileId) + " " + m_path + (m_directory ? " dir" : "")
                + (m_pipe ? " pipe" : "") + "]";
    }
}
