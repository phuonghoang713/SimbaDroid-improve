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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

/**
 * Tests of the request parsing helpers that deal with untrusted input.
 */
public class SMB2ParsingTest {

    @Test
    public void sharePathsAreNormalised() throws Exception {
        assertEquals("\\", SMB2FileOperations.toSharePath(""));
        assertEquals("\\", SMB2FileOperations.toSharePath("\\"));
        assertEquals("\\file.txt", SMB2FileOperations.toSharePath("file.txt"));
        assertEquals("\\dir\\file.txt", SMB2FileOperations.toSharePath("\\dir\\file.txt"));
        assertEquals("\\dir\\sub", SMB2FileOperations.toSharePath("dir\\sub\\"));
        assertEquals("\\.hidden\\..data", SMB2FileOperations.toSharePath(".hidden\\..data"));
        assertEquals("\\a b\\ü.txt", SMB2FileOperations.toSharePath("a b\\ü.txt"));
    }

    @Test
    public void pathsThatCouldEscapeTheShareAreRejected() {
        String[] invalid = {"..", "..\\x", "dir\\..\\..\\etc\\passwd", "dir\\..", ".", "dir\\.\\x", "dir\\\\x", "a/b", "/etc/passwd",
                "a\u0000b", "a\nb", "a*b", "a?b", "a<b", "a>b", "a|b", "a\"b", "c:\\x"};

        for (String name : invalid) {
            try {
                String path = SMB2FileOperations.toSharePath(name);
                fail("Path was accepted: " + name + " -> " + path);
            }
            catch (SMB2Exception ex) {
                assertEquals(SMB2.STATUS_OBJECT_NAME_INVALID, ex.getStatus());
            }
        }
    }

    @Test
    public void parentAndNameOfPath() {
        assertEquals("\\", SMB2FileOperations.parentOf("\\file.txt"));
        assertEquals("\\dir", SMB2FileOperations.parentOf("\\dir\\file.txt"));
        assertEquals("file.txt", SMB2FileOperations.nameOf("\\dir\\file.txt"));
        assertEquals("file.txt", SMB2FileOperations.nameOf("\\file.txt"));
    }

    @Test
    public void requestRangesAreValidated() throws Exception {
        byte[] buf = new byte[4 + SMB2.HEADER_LEN + 32];
        SMB2Request req = new SMB2Request(buf, 4, SMB2.HEADER_LEN + 32, false);

        assertEquals(4 + SMB2.HEADER_LEN, req.checkRange(SMB2.HEADER_LEN, 32));
        assertEquals(4 + SMB2.HEADER_LEN + 32, req.checkRange(SMB2.HEADER_LEN + 32, 0));

        int[][] invalid = {{SMB2.HEADER_LEN, 33}, {SMB2.HEADER_LEN + 33, 0}, {0, 8}, {SMB2.HEADER_LEN - 1, 1},
                {SMB2.HEADER_LEN, -1}, {Integer.MAX_VALUE, 1}, {SMB2.HEADER_LEN, Integer.MAX_VALUE}};

        for (int[] range : invalid) {
            try {
                req.checkRange(range[0], range[1]);
                fail("Range was accepted: " + range[0] + "/" + range[1]);
            }
            catch (SMB2Exception ex) {
                assertEquals(SMB2.STATUS_INVALID_PARAMETER, ex.getStatus());
            }
        }
    }

    @Test
    public void spnegoTokensRoundTrip() throws Exception {
        byte[] init = SPNEGOToken.buildServerInit();
        assertTrue(SPNEGOToken.isInitToken(init, 0, init.length));

        SPNEGOToken.Init parsed = SPNEGOToken.parseInit(init, 0, init.length);
        assertTrue(parsed.hasMech(SPNEGOToken.OID_NTLMSSP));
        assertTrue(parsed.isFirstMech(SPNEGOToken.OID_NTLMSSP));
        assertNull(parsed.mechToken);
        assertEquals(0x30, parsed.mechTypes[0]);

        byte[] token = new byte[300];
        token[0] = 'N';
        byte[] mic = new byte[16];
        mic[0] = 1;

        byte[] resp = SPNEGOToken.buildResp(SPNEGOToken.ACCEPT_INCOMPLETE, SPNEGOToken.OID_NTLMSSP, token, mic);
        assertTrue(SPNEGOToken.isRespToken(resp, 0, resp.length));

        SPNEGOToken.Resp parsedResp = SPNEGOToken.parseResp(resp, 0, resp.length);
        assertEquals(SPNEGOToken.ACCEPT_INCOMPLETE, parsedResp.negState);
        assertArrayEquals(SPNEGOToken.OID_NTLMSSP, parsedResp.supportedMech);
        assertArrayEquals(token, parsedResp.responseToken);
        assertArrayEquals(mic, parsedResp.mechListMIC);
    }

    @Test
    public void truncatedSpnegoTokensAreRejected() {
        byte[] resp = SPNEGOToken.buildResp(SPNEGOToken.ACCEPT_COMPLETED, SPNEGOToken.OID_NTLMSSP, new byte[40], new byte[16]);
        byte[] init = SPNEGOToken.buildServerInit();

        for (int len = 1; len < resp.length; len++) {
            try {
                SPNEGOToken.parseResp(resp, 0, len);
                fail("Truncated response token was accepted, length " + len);
            }
            catch (java.io.IOException expected) {
                // Expected
            }
        }

        for (int len = 1; len < init.length; len++) {
            try {
                SPNEGOToken.parseInit(init, 0, len);
                fail("Truncated init token was accepted, length " + len);
            }
            catch (java.io.IOException expected) {
                // Expected
            }
        }
    }

    @Test
    public void ntHashMatchesKnownValue() {
        // MD4 of the UTF-16LE encoding of "password"
        assertArrayEquals(SMB2CryptoTest.hex("8846f7eaee8fb117ad06bdd830b7586c"), NTLMSSPServer.ntHash("password"));
    }

    @Test
    public void malformedNtlmMessagesFailCleanly() {
        NTLMSSPServer ntlm = new NTLMSSPServer();
        NTLMSSPServer.AccountSource accounts = userName -> NTLMSSPServer.ntHash("secret");

        // Authenticate without a challenge having been issued
        assertEquals(NTLMSSPServer.Result.FAILED, ntlm.processAuthenticate(new byte[100], accounts));

        byte[] negotiate = new byte[32];
        System.arraycopy("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII), 0, negotiate, 0, 8);
        negotiate[8] = 1;
        byte[] challenge = ntlm.processNegotiate(negotiate, "server");
        assertTrue(NTLMSSPServer.isNTLMSSP(challenge));
        assertEquals(NTLMSSPServer.TYPE_CHALLENGE, NTLMSSPServer.messageType(challenge));

        // Fields that point outside of the message
        byte[] auth = new byte[72];
        System.arraycopy("NTLMSSP\0".getBytes(StandardCharsets.US_ASCII), 0, auth, 0, 8);
        auth[8] = 3;
        for (int field = 12; field <= 52; field += 8) {
            auth[field] = (byte) 0xFF;
            auth[field + 1] = (byte) 0xFF;
            auth[field + 4] = (byte) 0xF0;
            auth[field + 7] = (byte) 0x7F;
        }
        assertEquals(NTLMSSPServer.Result.FAILED, ntlm.processAuthenticate(auth, accounts));
        assertNull(ntlm.getSessionKey());
        assertFalse(ntlm.canSign());
    }
}
