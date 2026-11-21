/*
 * Copyright (C) 2006-2010 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */

package org.filesys.smb.server.nio;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import java.util.concurrent.locks.LockSupport;

import org.filesys.debug.Debug;
import org.filesys.smb.server.SMBPacketPool;
import org.filesys.smb.server.PacketHandler;
import org.filesys.smb.server.Protocol;
import org.filesys.util.HexDump;

/**
 * Channel Packet Handler Class
 *
 * <p>
 * Provides the base class for Java SocketChannel based packet handler implementations.
 *
 * @author gkspencer
 */
public abstract class ChannelPacketHandler extends PacketHandler {

    // Socket channel that this session is using.
    private SocketChannel m_sockChannel;

    // Number of times to yield before sleeping when a channel is not ready, the time to sleep for, and the time
    // after which a client that has stopped sending or receiving part way through a packet is given up on
    private static final int IOSpinCount = 20;
    private static final long IOWaitNanos = 500000L;
    private static final long IOStallTimeoutNanos = 60L * 1000000000L;

    // Buffer to read the request header
    protected byte[] m_headerBuf = new byte[4];

    /**
     * Class constructor
     *
     * @param sockChannel SocketChannel
     * @param typ         Protocol
     * @param name        String
     * @param shortName   String
     * @param packetPool  SMBPacketPool
     * @throws IOException If a network error occurs
     */
    public ChannelPacketHandler(SocketChannel sockChannel, Protocol typ, String name, String shortName, SMBPacketPool packetPool)
            throws IOException {

        super(typ, name, shortName, packetPool);

        m_sockChannel = sockChannel;

        // Set socket options
        m_sockChannel.socket().setTcpNoDelay(true);
        m_sockChannel.setOption(StandardSocketOptions.SO_SNDBUF, 256000);

        // Set the remote address
        setRemoteAddress(m_sockChannel.socket().getInetAddress());
    }

    /**
     * Return the socket channel
     *
     * @return SocketChannel
     */
    public final SocketChannel getSocketChannel() {
        return m_sockChannel;
    }

    /**
     * Return the count of available bytes in the receive input stream
     *
     * @return int
     * @throws IOException If a network error occurs.
     */
    public int availableBytes()
            throws IOException {

        return 0;
    }

    /**
     * Read bytes from the socket channel, without blocking
     *
     * @param pkt    byte[]
     * @param offset int
     * @param len    int
     * @return int Number of bytes read, zero if no data is available or -1 if the connection has been closed
     * @exception IOException Socket error
     */
    protected int readBytes(byte[] pkt, int offset, int len)
            throws IOException {

        // Wrap the buffer and read into it
        ByteBuffer buf = ByteBuffer.wrap(pkt, offset, len);
        return m_sockChannel.read(buf);
    }

    /**
     * Read a fixed number of bytes from the socket channel, waiting for the data to arrive if necessary. Used
     * to read the remainder of a request once the start of it has been received.
     *
     * @param pkt    byte[]
     * @param offset int
     * @param len    int
     * @exception IOException Socket error, the connection was closed or the client stopped sending
     */
    protected void readFully(byte[] pkt, int offset, int len)
            throws IOException {

        ByteBuffer buf = ByteBuffer.wrap(pkt, offset, len);
        int stalls = 0;
        long stallStart = 0L;

        while (buf.hasRemaining()) {
            int rdlen = m_sockChannel.read(buf);

            if (rdlen == -1)
                throw new IOException("Connection closed (request read)");

            if (rdlen > 0) {
                stalls = 0;
                continue;
            }

            if (stalls++ == 0)
                stallStart = System.nanoTime();
            waitForChannel(stalls, stallStart, "read");
        }
    }

    /**
     * Send a network packet
     *
     * @param pkt byte[]
     * @param off int
     * @param len int
     * @exception IOException I/O error, or the client stopped receiving
     */
    protected void writeBytes(byte[] pkt, int off, int len)
            throws IOException {

        // Wrap the buffer and output to the socket channel
        ByteBuffer buf = ByteBuffer.wrap(pkt, off, len);
        int stalls = 0;
        long stallStart = 0L;

        while (buf.hasRemaining()) {
            if (m_sockChannel.write(buf) > 0) {
                stalls = 0;
                continue;
            }

            // The socket send buffer is full, wait for the client to take some of the data
            if (stalls++ == 0)
                stallStart = System.nanoTime();
            waitForChannel(stalls, stallStart, "write");
        }
    }

    /**
     * Wait a short time for a non-blocking channel to become ready again, rather than spinning the CPU
     *
     * @param stalls     int Number of consecutive times that the channel was not ready
     * @param stallStart long Time that the channel was first found not to be ready
     * @param operation  String
     * @exception IOException The channel has not become ready for too long, or the thread was interrupted
     */
    private void waitForChannel(int stalls, long stallStart, String operation)
            throws IOException {

        if (Thread.currentThread().isInterrupted())
            throw new InterruptedIOException("Socket " + operation + " interrupted");

        // Data usually arrives or drains within a few microseconds, so yield a few times before sleeping
        if (stalls <= IOSpinCount) {
            Thread.yield();
            return;
        }

        if (System.nanoTime() - stallStart > IOStallTimeoutNanos)
            throw new IOException("Socket " + operation + " timed out");

        LockSupport.parkNanos(IOWaitNanos);
    }

    /**
     * Flush the output socket
     *
     * @throws IOException If a network error occurs
     */
    public void flushPacket()
            throws IOException {
    }

    @Override
    public boolean isClosed() {
        return m_sockChannel == null;
    }

    @Override
    public void closeHandler() {

        // Close the socket channel
        if (m_sockChannel != null) {

            try {

                // Close the associated socket
                if (m_sockChannel.socket() != null)
                    m_sockChannel.socket().close();

                // Close the channel
                m_sockChannel.close();
            }
            catch (IOException ex) {
            }
        }
    }
}
