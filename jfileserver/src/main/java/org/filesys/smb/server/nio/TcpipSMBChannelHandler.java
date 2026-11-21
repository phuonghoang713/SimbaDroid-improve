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
import java.nio.channels.SocketChannel;

import org.filesys.netbios.RFCNetBIOSProtocol;
import org.filesys.smb.TcpipSMB;
import org.filesys.smb.server.SMBPacketPool;
import org.filesys.smb.server.Protocol;
import org.filesys.smb.server.SMBSrvPacket;
import org.filesys.util.DataPacker;

/**
 * Tcpip SMB Packet Handler Class
 *
 * @author gkspencer
 */
public class TcpipSMBChannelHandler extends ChannelPacketHandler {

    /**
     * Class constructor
     *
     * @param sockChannel SocketChannel
     * @param packetPool  SMBPacketPool
     * @throws IOException If a network error occurs
     */
    public TcpipSMBChannelHandler(SocketChannel sockChannel, SMBPacketPool packetPool)
            throws IOException {
        super(sockChannel, Protocol.TCPIP, "TCP-SMB", "T", packetPool);
    }

    /**
     * Read a packet from the input stream
     *
     * @return SMBSrvPacket
     * @throws IOException If a network error occurs
     */
    public SMBSrvPacket readPacket()
            throws IOException {

        // Read the packet header
        int len = readBytes(m_headerBuf, 0, 4);

        // Check if the connection has been closed, read length equals -1, or there is no data available, read
        // length equals 0
        if (len <= 0)
            return null;

        // Short read of the packet header, can happen under heavy network load. Wait for the rest of it.
        if (len < TcpipSMB.HEADER_LEN)
            readFully(m_headerBuf, len, TcpipSMB.HEADER_LEN - len);

        // Get the data length from the header, a 24 bit value
        int dlen = ((m_headerBuf[1] & 0xFF) << 16) + ((m_headerBuf[2] & 0xFF) << 8) + (m_headerBuf[3] & 0xFF);

        // Do not let the client make us allocate more memory than it could have a use for
        if (dlen > getMaximumPacketSize())
            throw new IOException("Request too large, " + dlen + " bytes");

        // Get a packet from the pool to hold the request data, allow for the NetBIOS header length
        // so that the CIFS request lines up with other implementations.
        SMBSrvPacket pkt = getPacketPool().allocatePacket(dlen + getEncryptionOverhead() + TcpipSMB.HEADER_LEN);

        // Read the data part of the packet into the users buffer, this may take several reads
        try {
            if (dlen > 0)
                readFully(pkt.getBuffer(), RFCNetBIOSProtocol.HEADER_LEN, dlen);
        }
        catch (Throwable ex) {

            // Release the packet back to the pool
            getPacketPool().releasePacket(pkt);

            // Rethrow the exception
            rethrowException(ex);
        }

        // Set the received request length
        pkt.setReceivedLength(RFCNetBIOSProtocol.HEADER_LEN + dlen);

        // Return the received packet
        return pkt;
    }

    /**
     * Send a packet to the output stream
     *
     * @param pkt      SMBSrvPacket
     * @param len      int
     * @param writeRaw boolean
     * @throws IOException If a network error occurs
     */
    public void writePacket(SMBSrvPacket pkt, int len, boolean writeRaw)
            throws IOException {

        // Fill in the TCP SMB message header, this is already allocated as
        // part of the users buffer.
        byte[] buf = pkt.getBuffer();
        DataPacker.putInt(len, buf, 0);

        // Output the data packet
        int bufSiz = len + TcpipSMB.HEADER_LEN;
        writeBytes(buf, 0, bufSiz);
    }
}
