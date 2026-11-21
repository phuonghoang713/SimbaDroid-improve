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

package org.filesys.server.auth;

import java.net.InetAddress;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Limits the rate at which a client can guess passwords.
 *
 * <p>Failed logons are counted per client address. Once an address has reached the maximum number of failures, all
 * logons from it are refused until the lockout time has passed since the last failure that was counted. A successful
 * logon clears the count. With the defaults this allows at most 20 guesses per minute. Counting per address, rather than per account, means that an attacker cannot lock the legitimate user
 * out from another machine.
 */
public class LogonThrottle {

    public static final int DefaultMaxFailures = 20;
    public static final long DefaultLockoutMs = 60000L;

    // Maximum number of client addresses to track
    private static final int MaxEntries = 1024;

    private static final class Entry {
        int failures;
        long lastFailure;
    }

    private final int m_maxFailures;
    private final long m_lockoutMs;

    private final LinkedHashMap<InetAddress, Entry> m_entries = new LinkedHashMap<InetAddress, Entry>();

    public LogonThrottle() {
        this(DefaultMaxFailures, DefaultLockoutMs);
    }

    public LogonThrottle(int maxFailures, long lockoutMs) {
        m_maxFailures = maxFailures;
        m_lockoutMs = lockoutMs;
    }

    /**
     * Check if logons from a client address are currently being refused
     *
     * @param addr InetAddress
     * @return boolean
     */
    public boolean isBlocked(InetAddress addr) {
        return isBlocked(addr, System.currentTimeMillis());
    }

    synchronized boolean isBlocked(InetAddress addr, long now) {
        if (addr == null)
            return false;

        Entry entry = m_entries.get(addr);
        if (entry == null)
            return false;

        if (now - entry.lastFailure >= m_lockoutMs) {
            m_entries.remove(addr);
            return false;
        }

        // Attempts made during the lockout do not extend it. A client that keeps retrying with an outdated
        // password, such as a mapped network drive, would otherwise stay locked out for ever.
        return entry.failures >= m_maxFailures;
    }

    /**
     * Record a failed logon from a client address
     *
     * @param addr InetAddress
     */
    public void recordFailure(InetAddress addr) {
        recordFailure(addr, System.currentTimeMillis());
    }

    synchronized void recordFailure(InetAddress addr, long now) {
        if (addr == null)
            return;

        Entry entry = m_entries.get(addr);
        if (entry == null || now - entry.lastFailure >= m_lockoutMs) {
            if (entry == null && m_entries.size() >= MaxEntries)
                removeOldest(now);

            entry = new Entry();
            m_entries.put(addr, entry);
        }

        entry.failures++;
        entry.lastFailure = now;
    }

    /**
     * Record a successful logon from a client address
     *
     * @param addr InetAddress
     */
    public synchronized void recordSuccess(InetAddress addr) {
        if (addr != null)
            m_entries.remove(addr);
    }

    // Make room for a new entry, removing expired entries or failing that the oldest one
    private void removeOldest(long now) {
        Iterator<Map.Entry<InetAddress, Entry>> iter = m_entries.entrySet().iterator();
        boolean removed = false;

        while (iter.hasNext()) {
            if (now - iter.next().getValue().lastFailure >= m_lockoutMs) {
                iter.remove();
                removed = true;
            }
        }

        if (!removed) {
            iter = m_entries.entrySet().iterator();
            if (iter.hasNext()) {
                iter.next();
                iter.remove();
            }
        }
    }
}
