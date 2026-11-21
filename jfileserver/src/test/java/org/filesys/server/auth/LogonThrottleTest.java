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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;

import org.junit.Test;

public class LogonThrottleTest {

    private static InetAddress addr(int last) throws Exception {
        return InetAddress.getByAddress(new byte[]{10, 0, (byte) (last >> 8), (byte) last});
    }

    @Test
    public void blocksAfterTooManyFailuresAndRecovers() throws Exception {
        LogonThrottle throttle = new LogonThrottle(3, 1000L);
        InetAddress client = addr(1);

        throttle.recordFailure(client, 100);
        throttle.recordFailure(client, 200);
        assertFalse(throttle.isBlocked(client, 250));

        throttle.recordFailure(client, 300);
        assertTrue(throttle.isBlocked(client, 301));
        assertTrue(throttle.isBlocked(client, 1299));

        // Attempts during the lockout do not extend it
        assertFalse(throttle.isBlocked(client, 1300));

        // The count starts again afterwards
        throttle.recordFailure(client, 1400);
        assertFalse(throttle.isBlocked(client, 1401));
    }

    @Test
    public void successClearsTheCount() throws Exception {
        LogonThrottle throttle = new LogonThrottle(3, 1000L);
        InetAddress client = addr(1);

        throttle.recordFailure(client, 100);
        throttle.recordFailure(client, 110);
        throttle.recordSuccess(client);
        throttle.recordFailure(client, 120);
        throttle.recordFailure(client, 130);
        assertFalse(throttle.isBlocked(client, 140));
    }

    @Test
    public void clientsAreCountedSeparately() throws Exception {
        LogonThrottle throttle = new LogonThrottle(2, 1000L);

        throttle.recordFailure(addr(1), 100);
        throttle.recordFailure(addr(1), 110);
        assertTrue(throttle.isBlocked(addr(1), 120));
        assertFalse(throttle.isBlocked(addr(2), 120));
        assertFalse(throttle.isBlocked(null, 120));
    }

    @Test
    public void numberOfTrackedClientsIsBounded() throws Exception {
        LogonThrottle throttle = new LogonThrottle(1, 1000000L);

        // Far more addresses than are tracked, the most recent ones must still be blocked
        for (int i = 0; i < 5000; i++)
            throttle.recordFailure(addr(i), 100 + i);

        assertTrue(throttle.isBlocked(addr(4999), 6000));
        assertFalse(throttle.isBlocked(addr(0), 6000));
    }
}
