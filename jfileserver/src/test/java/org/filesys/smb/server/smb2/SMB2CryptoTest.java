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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

/**
 * Tests of the SMB2/SMB3 signing, key derivation and encryption primitives against published test vectors.
 */
public class SMB2CryptoTest {

    static byte[] hex(String str) {
        str = str.replace(" ", "");
        byte[] byts = new byte[str.length() / 2];
        for (int i = 0; i < byts.length; i++)
            byts[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);
        return byts;
    }

    // AES-CMAC test vectors from RFC 4493 section 4
    private static final byte[] CMAC_KEY = hex("2b7e151628aed2a6abf7158809cf4f3c");
    private static final byte[] CMAC_MSG = hex("6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51"
            + "30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710");

    @Test
    public void aesCmacMatchesRfc4493Vectors() throws Exception {
        assertArrayEquals(hex("bb1d6929e95937287fa37d129b756746"), SMB2Crypto.aesCmac(CMAC_KEY, CMAC_MSG, 0, 0));
        assertArrayEquals(hex("070a16b46b4d4144f79bdd9dd04a287c"), SMB2Crypto.aesCmac(CMAC_KEY, CMAC_MSG, 0, 16));
        assertArrayEquals(hex("dfa66747de9ae63030ca32611497c827"), SMB2Crypto.aesCmac(CMAC_KEY, CMAC_MSG, 0, 40));
        assertArrayEquals(hex("51f0bebf7e3b9d92fc49741779363cfe"), SMB2Crypto.aesCmac(CMAC_KEY, CMAC_MSG, 0, 64));
    }

    @Test
    public void aesCmacHandlesOffsetsAndLargeMessages() throws Exception {
        // The message is processed in chunks, check that a message spanning several chunks gives the same result
        // regardless of where it starts in the buffer
        byte[] msg = new byte[300000 + 7];
        new Random(1).nextBytes(msg);

        byte[] shifted = new byte[msg.length + 13];
        System.arraycopy(msg, 0, shifted, 13, msg.length);

        byte[] mac = SMB2Crypto.aesCmac(CMAC_KEY, msg, 0, msg.length);
        assertArrayEquals(mac, SMB2Crypto.aesCmac(CMAC_KEY, shifted, 13, msg.length));

        msg[150000] ^= 1;
        assertFalse(Arrays.equals(mac, SMB2Crypto.aesCmac(CMAC_KEY, msg, 0, msg.length)));
    }

    @Test
    public void keyDerivationMatchesPublishedSmb30Vectors() throws Exception {
        // From the Microsoft "SMB 2 and SMB 3 security in Windows 10: the anatomy of signing and cryptographic
        // keys" article, SMB 3.0 example
        byte[] sessionKey = hex("7CD451825D0450D235424E44BA6E78CC");

        assertArrayEquals(hex("0B7E9C5CAC36C0F6EA9AB275298CEDCE"),
                SMB2Crypto.deriveSigningKey(SMB2.DIALECT_300, sessionKey, null));
        assertArrayEquals(hex("B0F0427F7CEB416D1D9DCC0CD4F99447"),
                SMB2Crypto.deriveEncryptionKey(SMB2.DIALECT_300, sessionKey, null));
    }

    @Test
    public void smb2SigningKeyIsTheSessionKey() throws Exception {
        byte[] sessionKey = hex("000102030405060708090a0b0c0d0e0f");
        assertArrayEquals(sessionKey, SMB2Crypto.deriveSigningKey(SMB2.DIALECT_210, sessionKey, null));
    }

    @Test
    public void smb311KeysDependOnThePreauthHash() throws Exception {
        byte[] sessionKey = hex("000102030405060708090a0b0c0d0e0f");
        byte[] hash1 = new byte[64];
        byte[] hash2 = new byte[64];
        hash2[0] = 1;

        byte[] key1 = SMB2Crypto.deriveSigningKey(SMB2.DIALECT_311, sessionKey, hash1);
        byte[] key2 = SMB2Crypto.deriveSigningKey(SMB2.DIALECT_311, sessionKey, hash2);

        assertEquals(16, key1.length);
        assertFalse(Arrays.equals(key1, key2));
        assertFalse(Arrays.equals(key1, SMB2Crypto.deriveEncryptionKey(SMB2.DIALECT_311, sessionKey, hash1)));
        assertFalse(Arrays.equals(SMB2Crypto.deriveDecryptionKey(SMB2.DIALECT_311, sessionKey, hash1),
                SMB2Crypto.deriveEncryptionKey(SMB2.DIALECT_311, sessionKey, hash1)));
    }

    private static byte[] sampleMessage(int bodyLen) {
        byte[] msg = new byte[SMB2.HEADER_LEN + bodyLen];
        new Random(bodyLen).nextBytes(msg);
        msg[0] = (byte) 0xFE;
        msg[1] = 'S';
        msg[2] = 'M';
        msg[3] = 'B';
        return msg;
    }

    @Test
    public void signaturesVerifyAndDetectTampering() throws Exception {
        byte[] key = hex("0B7E9C5CAC36C0F6EA9AB275298CEDCE");

        for (int dialect : new int[]{SMB2.DIALECT_202, SMB2.DIALECT_210, SMB2.DIALECT_300, SMB2.DIALECT_302, SMB2.DIALECT_311}) {
            for (int bodyLen : new int[]{9, 16, 100, 65536, 70001}) {
                byte[] msg = sampleMessage(bodyLen);
                SMB2Crypto.signMessage(dialect, key, msg, 0, msg.length);

                assertTrue(SMB2Crypto.verifySignature(dialect, key, msg.clone(), 0, msg.length));

                // Changed data
                byte[] tampered = msg.clone();
                tampered[SMB2.HEADER_LEN + bodyLen - 1] ^= 0x01;
                assertFalse(SMB2Crypto.verifySignature(dialect, key, tampered, 0, tampered.length));

                // Changed header field
                tampered = msg.clone();
                tampered[SMB2.OFF_COMMAND] ^= 0x01;
                assertFalse(SMB2Crypto.verifySignature(dialect, key, tampered, 0, tampered.length));

                // Wrong key
                byte[] wrongKey = key.clone();
                wrongKey[5] ^= 0x10;
                assertFalse(SMB2Crypto.verifySignature(dialect, wrongKey, msg.clone(), 0, msg.length));
            }
        }
    }

    @Test
    public void hmacAndCmacSignaturesDiffer() throws Exception {
        byte[] key = hex("0B7E9C5CAC36C0F6EA9AB275298CEDCE");
        byte[] msg = sampleMessage(64);
        Arrays.fill(msg, SMB2.OFF_SIGNATURE, SMB2.OFF_SIGNATURE + 16, (byte) 0);

        assertFalse(Arrays.equals(SMB2Crypto.calculateSignature(SMB2.DIALECT_210, key, msg, 0, msg.length),
                SMB2Crypto.calculateSignature(SMB2.DIALECT_300, key, msg, 0, msg.length)));
    }

    @Test
    public void encryptionRoundTripsAndAuthenticates() throws Exception {
        byte[] key = hex("B0F0427F7CEB416D1D9DCC0CD4F99447");
        long sessionId = 0x1122334455667788L;

        for (int cipher : new int[]{SMB2.CIPHER_AES128_CCM, SMB2.CIPHER_AES128_GCM}) {
            for (int bodyLen : new int[]{9, 300, 70000}) {
                byte[] msg = sampleMessage(bodyLen);
                byte[] enc = new byte[4 + SMB2.TRANSFORM_HEADER_LEN + msg.length + SMB2.SIGNATURE_LEN];

                int encLen = SMB2Crypto.encryptMessage(cipher, key, sessionId, msg, 0, msg.length, enc, 4);
                assertEquals(SMB2.TRANSFORM_HEADER_LEN + msg.length, encLen);
                assertEquals((byte) 0xFD, enc[4]);
                assertEquals(sessionId, SMB2Buf.getLong(enc, 4 + SMB2.TF_OFF_SESSION_ID));
                assertEquals(msg.length, SMB2Buf.getInt(enc, 4 + SMB2.TF_OFF_ORIG_SIZE));

                // The payload must not appear in the clear
                assertFalse(Arrays.equals(Arrays.copyOfRange(enc, 4 + SMB2.TRANSFORM_HEADER_LEN, 4 + encLen), msg));

                assertArrayEquals(msg, SMB2Crypto.decryptMessage(cipher, key, enc, 4, encLen));

                // A change to the ciphertext, the authenticated header or the tag must be detected
                for (int pos : new int[]{4 + SMB2.TRANSFORM_HEADER_LEN + 3, 4 + SMB2.TF_OFF_SESSION_ID, 4 + SMB2.TF_OFF_SIGNATURE}) {
                    byte[] tampered = enc.clone();
                    tampered[pos] ^= 0x01;
                    try {
                        SMB2Crypto.decryptMessage(cipher, key, tampered, 4, encLen);
                        fail("Tampering at " + pos + " was not detected, cipher " + cipher);
                    }
                    catch (GeneralSecurityException expected) {
                        // Expected
                    }
                }
            }
        }
    }

    @Test
    public void encryptionUsesAFreshNonce() throws Exception {
        byte[] key = hex("B0F0427F7CEB416D1D9DCC0CD4F99447");
        byte[] msg = sampleMessage(32);

        byte[] enc1 = new byte[4 + SMB2.TRANSFORM_HEADER_LEN + msg.length + SMB2.SIGNATURE_LEN];
        byte[] enc2 = new byte[enc1.length];
        SMB2Crypto.encryptMessage(SMB2.CIPHER_AES128_GCM, key, 1L, msg, 0, msg.length, enc1, 4);
        SMB2Crypto.encryptMessage(SMB2.CIPHER_AES128_GCM, key, 1L, msg, 0, msg.length, enc2, 4);

        assertFalse(Arrays.equals(enc1, enc2));
    }

    @Test
    public void preauthHashChainsMessages() throws Exception {
        byte[] hash = new byte[64];
        byte[] msg1 = sampleMessage(10);
        byte[] msg2 = sampleMessage(20);

        byte[] h1 = SMB2Crypto.updatePreauthHash(hash, msg1, 0, msg1.length);
        byte[] h2 = SMB2Crypto.updatePreauthHash(h1, msg2, 0, msg2.length);

        assertEquals(64, h2.length);
        assertFalse(Arrays.equals(h1, h2));
        assertArrayEquals(h2, SMB2Crypto.updatePreauthHash(SMB2Crypto.updatePreauthHash(new byte[64], msg1, 0, msg1.length),
                msg2, 0, msg2.length));
    }
}
