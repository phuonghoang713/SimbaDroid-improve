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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Byte range lock manager for SMB2 opens.
 *
 * <p>Locks are held in memory and are shared between all SMB2 connections, so that clients can use them to
 * coordinate access to a file. Lock requests are never queued, a request that conflicts with an existing lock
 * fails immediately.
 */
final class SMB2LockManager {

    /**
     * A locked byte range
     */
    private static final class Range {
        final long offset;
        final long length;
        final boolean exclusive;
        final SMB2Open owner;

        Range(long offset, long length, boolean exclusive, SMB2Open owner) {
            this.offset = offset;
            this.length = length;
            this.exclusive = exclusive;
            this.owner = owner;
        }

        boolean overlaps(long off, long len) {
            if (length == 0 || len == 0)
                return false;

            // Unsigned comparison of [offset, offset + length) and [off, off + len)
            return Long.compareUnsigned(offset, endOf(off, len)) <= 0 && Long.compareUnsigned(off, endOf(offset, length)) <= 0;
        }

        // Return the offset of the last byte of a range, clamped to the largest unsigned value
        private static long endOf(long off, long len) {
            long end = off + len - 1;
            return Long.compareUnsigned(end, off) < 0 ? -1L : end;
        }
    }

    // Maximum number of locked ranges on one file
    private static final int MAX_RANGES_PER_FILE = 1024;

    // Locked ranges by file. All access is synchronised on the map, lock requests are rare compared with reads
    // and writes, which only look at the count below unless there are locks.
    private static final Map<String, List<Range>> s_locks = new HashMap<String, List<Range>>();

    private static volatile int s_fileCount;

    private SMB2LockManager() {
    }

    private static String keyFor(SMB2Open open) {
        return open.getTree().getSharedDevice().getName() + "|" + open.getPath().toLowerCase(Locale.ROOT);
    }

    /**
     * Check if any locks are held, used to skip the lock checks on the read/write path
     *
     * @return boolean
     */
    static boolean hasLocks() {
        return s_fileCount > 0;
    }

    /**
     * Try to lock a byte range
     *
     * @param open      SMB2Open
     * @param offset    long
     * @param length    long
     * @param exclusive boolean
     * @return boolean false if the range conflicts with an existing lock, or the file has too many locks
     */
    static boolean lock(SMB2Open open, long offset, long length, boolean exclusive) {
        synchronized (s_locks) {
            if (open.lockKey == null)
                open.lockKey = keyFor(open);

            List<Range> ranges = s_locks.get(open.lockKey);

            if (ranges != null) {
                if (ranges.size() >= MAX_RANGES_PER_FILE)
                    return false;

                for (Range range : ranges) {
                    if ((exclusive || range.exclusive) && range.overlaps(offset, length))
                        return false;
                }
            }
            else {
                ranges = new ArrayList<Range>(4);
                s_locks.put(open.lockKey, ranges);
                s_fileCount = s_locks.size();
            }

            ranges.add(new Range(offset, length, exclusive, open));
            open.hasLocks = true;
            return true;
        }
    }

    /**
     * Unlock a byte range, which must match a range previously locked by the open
     *
     * @param open   SMB2Open
     * @param offset long
     * @param length long
     * @return boolean false if the range is not locked by the open
     */
    static boolean unlock(SMB2Open open, long offset, long length) {
        synchronized (s_locks) {
            List<Range> ranges = open.lockKey != null ? s_locks.get(open.lockKey) : null;
            if (ranges == null)
                return false;

            Iterator<Range> iter = ranges.iterator();
            while (iter.hasNext()) {
                Range range = iter.next();
                if (range.owner == open && range.offset == offset && range.length == length) {
                    iter.remove();
                    removeIfEmpty(open.lockKey, ranges);
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Release all locks held by an open
     *
     * @param open SMB2Open
     */
    static void releaseLocks(SMB2Open open) {
        synchronized (s_locks) {
            List<Range> ranges = open.lockKey != null ? s_locks.get(open.lockKey) : null;

            if (ranges != null) {
                Iterator<Range> iter = ranges.iterator();
                while (iter.hasNext()) {
                    if (iter.next().owner == open)
                        iter.remove();
                }
                removeIfEmpty(open.lockKey, ranges);
            }
            open.hasLocks = false;
        }
    }

    private static void removeIfEmpty(String key, List<Range> ranges) {
        if (ranges.isEmpty()) {
            s_locks.remove(key);
            s_fileCount = s_locks.size();
        }
    }

    /**
     * Check if a read or write by an open is blocked by a lock held by another open
     *
     * @param open   SMB2Open
     * @param offset long
     * @param length long
     * @param write  boolean
     * @return boolean true if the I/O is allowed
     */
    static boolean canAccess(SMB2Open open, long offset, long length, boolean write) {
        synchronized (s_locks) {
            List<Range> ranges = s_locks.get(open.lockKey != null ? open.lockKey : keyFor(open));
            if (ranges == null)
                return true;

            for (Range range : ranges) {
                if (range.owner != open && (write || range.exclusive) && range.overlaps(offset, length))
                    return false;
            }
            return true;
        }
    }
}
