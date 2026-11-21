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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Cryptographic helpers for SMB2/SMB3: key derivation, message signing and message encryption.
 *
 * <p>The bulk operations use the platform JCE providers where possible (HMAC-SHA256, AES-CBC for CMAC, AES-GCM) as
 * these are hardware accelerated on most devices. AES-CCM is not reliably available via JCE so the BouncyCastle
 * lightweight API is used for that mode.
 */
public final class SMB2Crypto {

    private static final SecureRandom s_random = new SecureRandom();

    private static final int AES_BLOCK = 16;
    private static final IvParameterSpec ZERO_IV = new IvParameterSpec(new byte[AES_BLOCK]);

    // Scratch buffer size used when running a CBC-MAC over a large message
    private static final int CMAC_CHUNK = 32 * 1024;

    private static final ThreadLocal<byte[]> s_scratch = new ThreadLocal<byte[]>() {
        @Override
        protected byte[] initialValue() {
            return new byte[CMAC_CHUNK + AES_BLOCK];
        }
    };

    // Key derivation labels/contexts, including the terminating null
    private static final byte[] LBL_SIGN_30 = cstr("SMB2AESCMAC");
    private static final byte[] CTX_SIGN_30 = cstr("SmbSign");
    private static final byte[] LBL_ENC_30 = cstr("SMB2AESCCM");
    private static final byte[] CTX_ENC_IN_30 = cstr("ServerIn ");
    private static final byte[] CTX_ENC_OUT_30 = cstr("ServerOut");
    private static final byte[] LBL_SIGN_311 = cstr("SMBSigningKey");
    private static final byte[] LBL_C2S_311 = cstr("SMBC2SCipherKey");
    private static final byte[] LBL_S2C_311 = cstr("SMBS2CCipherKey");

    private SMB2Crypto() {
    }

    private static byte[] cstr(String s) {
        byte[] ascii = s.getBytes(StandardCharsets.US_ASCII);
        return Arrays.copyOf(ascii, ascii.length + 1);
    }

    public static byte[] randomBytes(int len) {
        byte[] byts = new byte[len];
        s_random.nextBytes(byts);
        return byts;
    }

    public static long randomLong() {
        return s_random.nextLong();
    }

    /**
     * SP800-108 counter mode KDF using HMAC-SHA256, producing a 128 bit key
     *
     * @param key     byte[]
     * @param label   byte[] Label including its null terminator
     * @param context byte[]
     * @return byte[]
     * @exception GeneralSecurityException Crypto error
     */
    public static byte[] deriveKey(byte[] key, byte[] label, byte[] context)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(new byte[]{0, 0, 0, 1});
        mac.update(label);
        mac.update((byte) 0);
        mac.update(context);
        mac.update(new byte[]{0, 0, 0, (byte) 128});
        return Arrays.copyOf(mac.doFinal(), 16);
    }

    /**
     * Derive the signing key for a session
     *
     * @param dialect     int SMB2 dialect revision
     * @param sessionKey  byte[] 16 byte session key
     * @param preauthHash byte[] Session pre-authentication integrity hash, for SMB 3.1.1
     * @return byte[]
     * @exception GeneralSecurityException Crypto error
     */
    public static byte[] deriveSigningKey(int dialect, byte[] sessionKey, byte[] preauthHash)
            throws GeneralSecurityException {
        if (dialect < SMB2.DIALECT_300)
            return sessionKey;
        if (dialect >= SMB2.DIALECT_311)
            return deriveKey(sessionKey, LBL_SIGN_311, preauthHash);
        return deriveKey(sessionKey, LBL_SIGN_30, CTX_SIGN_30);
    }

    /**
     * Derive the key used to decrypt requests received from the client
     *
     * @param dialect     int
     * @param sessionKey  byte[]
     * @param preauthHash byte[]
     * @return byte[]
     * @exception GeneralSecurityException Crypto error
     */
    public static byte[] deriveDecryptionKey(int dialect, byte[] sessionKey, byte[] preauthHash)
            throws GeneralSecurityException {
        if (dialect >= SMB2.DIALECT_311)
            return deriveKey(sessionKey, LBL_C2S_311, preauthHash);
        return deriveKey(sessionKey, LBL_ENC_30, CTX_ENC_IN_30);
    }

    /**
     * Derive the key used to encrypt responses sent to the client
     *
     * @param dialect     int
     * @param sessionKey  byte[]
     * @param preauthHash byte[]
     * @return byte[]
     * @exception GeneralSecurityException Crypto error
     */
    public static byte[] deriveEncryptionKey(int dialect, byte[] sessionKey, byte[] preauthHash)
            throws GeneralSecurityException {
        if (dialect >= SMB2.DIALECT_311)
            return deriveKey(sessionKey, LBL_S2C_311, preauthHash);
        return deriveKey(sessionKey, LBL_ENC_30, CTX_ENC_OUT_30);
    }

    /**
     * Update a pre-authentication integrity hash value with a message, H = SHA-512(H || message)
     *
     * @param hash byte[] Current hash value, 64 bytes
     * @param buf  byte[]
     * @param off  int
     * @param len  int
     * @return byte[] New hash value
     * @exception GeneralSecurityException Crypto error
     */
    public static byte[] updatePreauthHash(byte[] hash, byte[] buf, int off, int len)
            throws GeneralSecurityException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        sha512.update(hash);
        sha512.update(buf, off, len);
        return sha512.digest();
    }

    /**
     * Calculate the signature of an SMB2 message. The signature field of the message must already be zeroed.
     *
     * @param dialect int
     * @param key     byte[] Signing key
     * @param buf     byte[]
     * @param off     int Offset of the SMB2 header
     * @param len     int Message length
     * @return byte[] 16 byte signature
     * @exception GeneralSecurityException Crypto error
     */
    public static byte[] calculateSignature(int dialect, byte[] key, byte[] buf, int off, int len)
            throws GeneralSecurityException {
        if (dialect >= SMB2.DIALECT_300)
            return aesCmac(key, buf, off, len);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(buf, off, len);
        return Arrays.copyOf(mac.doFinal(), SMB2.SIGNATURE_LEN);
    }

    /**
     * Sign an SMB2 message in place
     *
     * @param dialect int
     * @param key     byte[]
     * @param buf     byte[]
     * @param off     int
     * @param len     int
     * @exception GeneralSecurityException Crypto error
     */
    public static void signMessage(int dialect, byte[] key, byte[] buf, int off, int len)
            throws GeneralSecurityException {
        Arrays.fill(buf, off + SMB2.OFF_SIGNATURE, off + SMB2.OFF_SIGNATURE + SMB2.SIGNATURE_LEN, (byte) 0);
        byte[] sig = calculateSignature(dialect, key, buf, off, len);
        System.arraycopy(sig, 0, buf, off + SMB2.OFF_SIGNATURE, SMB2.SIGNATURE_LEN);
    }

    /**
     * Verify the signature of a received SMB2 message. The signature field is zeroed by the check.
     *
     * @param dialect int
     * @param key     byte[]
     * @param buf     byte[]
     * @param off     int
     * @param len     int
     * @return boolean
     * @exception GeneralSecurityException Crypto error
     */
    public static boolean verifySignature(int dialect, byte[] key, byte[] buf, int off, int len)
            throws GeneralSecurityException {
        byte[] rxSig = Arrays.copyOfRange(buf, off + SMB2.OFF_SIGNATURE, off + SMB2.OFF_SIGNATURE + SMB2.SIGNATURE_LEN);
        Arrays.fill(buf, off + SMB2.OFF_SIGNATURE, off + SMB2.OFF_SIGNATURE + SMB2.SIGNATURE_LEN, (byte) 0);
        byte[] sig = calculateSignature(dialect, key, buf, off, len);
        return MessageDigest.isEqual(rxSig, sig);
    }

    /**
     * AES-128-CMAC (RFC 4493). Implemented as a CBC-MAC over the message with the final block adjusted, so that the
     * bulk of the work is done by the platform AES-CBC implementation.
     *
     * @param key byte[]
     * @param buf byte[]
     * @param off int
     * @param len int
     * @return byte[] 16 byte MAC
     * @exception GeneralSecurityException Crypto error
     */
    public static byte[] aesCmac(byte[] key, byte[] buf, int off, int len)
            throws GeneralSecurityException {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        // Generate the subkeys
        Cipher ecb = Cipher.getInstance("AES/ECB/NoPadding");
        ecb.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] k1 = cmacDouble(ecb.doFinal(new byte[AES_BLOCK]));

        // Build the adjusted final block
        int blocks = (len + AES_BLOCK - 1) / AES_BLOCK;
        if (blocks == 0)
            blocks = 1;
        int lastOff = (blocks - 1) * AES_BLOCK;
        int lastLen = len - lastOff;

        byte[] last = new byte[AES_BLOCK];
        System.arraycopy(buf, off + lastOff, last, 0, lastLen);

        byte[] subKey = k1;
        if (lastLen != AES_BLOCK) {
            last[lastLen] = (byte) 0x80;
            subKey = cmacDouble(k1);
        }
        for (int i = 0; i < AES_BLOCK; i++)
            last[i] ^= subKey[i];

        // Run the CBC-MAC, the MAC is the last ciphertext block
        Cipher cbc = Cipher.getInstance("AES/CBC/NoPadding");
        cbc.init(Cipher.ENCRYPT_MODE, keySpec, ZERO_IV);

        byte[] scratch = s_scratch.get();
        byte[] mac = new byte[AES_BLOCK];
        int done = 0;

        while (done < lastOff) {
            int chunk = Math.min(CMAC_CHUNK, lastOff - done);
            int outLen = cbc.update(buf, off + done, chunk, scratch, 0);
            if (outLen >= AES_BLOCK)
                System.arraycopy(scratch, outLen - AES_BLOCK, mac, 0, AES_BLOCK);
            done += chunk;
        }

        int outLen = cbc.doFinal(last, 0, AES_BLOCK, scratch, 0);
        if (outLen >= AES_BLOCK)
            System.arraycopy(scratch, outLen - AES_BLOCK, mac, 0, AES_BLOCK);

        return mac;
    }

    /**
     * Doubling in GF(2^128), used to generate the CMAC subkeys
     *
     * @param in byte[]
     * @return byte[]
     */
    private static byte[] cmacDouble(byte[] in) {
        byte[] out = new byte[AES_BLOCK];
        int carry = 0;
        for (int i = AES_BLOCK - 1; i >= 0; i--) {
            int b = in[i] & 0xFF;
            out[i] = (byte) ((b << 1) | carry);
            carry = b >>> 7;
        }
        if (carry != 0)
            out[AES_BLOCK - 1] ^= (byte) 0x87;
        return out;
    }

    /**
     * Return the nonce length used by a cipher
     *
     * @param cipherId int
     * @return int
     */
    public static int nonceLength(int cipherId) {
        return cipherId == SMB2.CIPHER_AES128_GCM ? 12 : 11;
    }

    /**
     * Encrypt one or more SMB2 messages, producing a transform header followed by the ciphertext.
     *
     * @param cipherId  int
     * @param key       byte[] Server to client cipher key
     * @param sessionId long
     * @param msg       byte[] Plaintext message buffer
     * @param msgOff    int
     * @param msgLen    int
     * @param out       byte[] Output buffer, must have room for outOff + 52 + msgLen + 16 bytes
     * @param outOff    int Offset to write the transform header at
     * @return int Length of the transform header plus ciphertext
     * @exception GeneralSecurityException Crypto error
     */
    public static int encryptMessage(int cipherId, byte[] key, long sessionId, byte[] msg, int msgOff, int msgLen,
                                     byte[] out, int outOff)
            throws GeneralSecurityException {

        // Build the transform header
        Arrays.fill(out, outOff, outOff + SMB2.TRANSFORM_HEADER_LEN, (byte) 0);
        out[outOff] = (byte) 0xFD;
        out[outOff + 1] = 'S';
        out[outOff + 2] = 'M';
        out[outOff + 3] = 'B';

        int nonceLen = nonceLength(cipherId);
        byte[] nonce = randomBytes(nonceLen);
        System.arraycopy(nonce, 0, out, outOff + SMB2.TF_OFF_NONCE, nonceLen);

        putInt(out, outOff + SMB2.TF_OFF_ORIG_SIZE, msgLen);
        out[outOff + SMB2.TF_OFF_FLAGS] = 0x01;    // encrypted
        putInt(out, outOff + SMB2.TF_OFF_SESSION_ID, (int) sessionId);
        putInt(out, outOff + SMB2.TF_OFF_SESSION_ID + 4, (int) (sessionId >>> 32));

        int aadOff = outOff + SMB2.TF_OFF_NONCE;
        int aadLen = SMB2.TRANSFORM_HEADER_LEN - SMB2.TF_OFF_NONCE;
        int ctOff = outOff + SMB2.TRANSFORM_HEADER_LEN;

        // Ciphertext is written directly after the header, followed by the 16 byte tag which is then moved
        // into the signature field of the header
        if (cipherId == SMB2.CIPHER_AES128_GCM) {
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            gcm.updateAAD(out, aadOff, aadLen);
            int outLen = gcm.doFinal(msg, msgOff, msgLen, out, ctOff);
            if (outLen != msgLen + SMB2.SIGNATURE_LEN)
                throw new GeneralSecurityException("Unexpected GCM output length " + outLen);
        }
        else if (cipherId == SMB2.CIPHER_AES128_CCM) {
            CCMBlockCipher ccm = newCcm();
            byte[] aad = Arrays.copyOfRange(out, aadOff, aadOff + aadLen);
            ccm.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
            try {
                ccm.processPacket(msg, msgOff, msgLen, out, ctOff);
            }
            catch (Exception ex) {
                throw new GeneralSecurityException("CCM encryption failed", ex);
            }
        }
        else
            throw new GeneralSecurityException("Unsupported cipher " + cipherId);

        System.arraycopy(out, ctOff + msgLen, out, outOff + SMB2.TF_OFF_SIGNATURE, SMB2.SIGNATURE_LEN);

        return SMB2.TRANSFORM_HEADER_LEN + msgLen;
    }

    /**
     * Decrypt an encrypted SMB2 message
     *
     * @param cipherId int
     * @param key      byte[] Client to server cipher key
     * @param buf      byte[] Buffer holding the transform header and ciphertext
     * @param off      int Offset of the transform header
     * @param len      int Length of the transform header plus ciphertext
     * @return byte[] Decrypted message(s)
     * @exception GeneralSecurityException Decryption or authentication failure
     */
    public static byte[] decryptMessage(int cipherId, byte[] key, byte[] buf, int off, int len)
            throws GeneralSecurityException {

        int ctLen = len - SMB2.TRANSFORM_HEADER_LEN;
        int origSize = getInt(buf, off + SMB2.TF_OFF_ORIG_SIZE);
        if (ctLen < 0 || origSize != ctLen)
            throw new GeneralSecurityException("Invalid transform header length");

        int nonceLen = nonceLength(cipherId);
        byte[] nonce = Arrays.copyOfRange(buf, off + SMB2.TF_OFF_NONCE, off + SMB2.TF_OFF_NONCE + nonceLen);

        int aadOff = off + SMB2.TF_OFF_NONCE;
        int aadLen = SMB2.TRANSFORM_HEADER_LEN - SMB2.TF_OFF_NONCE;
        int ctOff = off + SMB2.TRANSFORM_HEADER_LEN;
        int tagOff = off + SMB2.TF_OFF_SIGNATURE;

        byte[] plain = new byte[ctLen];

        if (cipherId == SMB2.CIPHER_AES128_GCM) {
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            gcm.updateAAD(buf, aadOff, aadLen);

            // The tag is held in the header rather than following the ciphertext
            int outLen = 0;
            byte[] part = gcm.update(buf, ctOff, ctLen);
            if (part != null && part.length > 0) {
                System.arraycopy(part, 0, plain, 0, part.length);
                outLen = part.length;
            }
            part = gcm.doFinal(buf, tagOff, SMB2.SIGNATURE_LEN);
            if (part != null && part.length > 0) {
                System.arraycopy(part, 0, plain, outLen, part.length);
                outLen += part.length;
            }
            if (outLen != ctLen)
                throw new GeneralSecurityException("Unexpected GCM output length " + outLen);
        }
        else if (cipherId == SMB2.CIPHER_AES128_CCM) {
            CCMBlockCipher ccm = newCcm();
            byte[] aad = Arrays.copyOfRange(buf, aadOff, aadOff + aadLen);
            ccm.init(false, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
            try {
                ccm.processBytes(buf, ctOff, ctLen, null, 0);
                ccm.processBytes(buf, tagOff, SMB2.SIGNATURE_LEN, null, 0);
                ccm.doFinal(plain, 0);
            }
            catch (Exception ex) {
                throw new GeneralSecurityException("CCM decryption failed", ex);
            }
        }
        else
            throw new GeneralSecurityException("Unsupported cipher " + cipherId);

        return plain;
    }

    @SuppressWarnings("deprecation")
    private static CCMBlockCipher newCcm() {
        return new CCMBlockCipher(new AESEngine());
    }

    private static void putInt(byte[] buf, int pos, int val) {
        buf[pos] = (byte) val;
        buf[pos + 1] = (byte) (val >> 8);
        buf[pos + 2] = (byte) (val >> 16);
        buf[pos + 3] = (byte) (val >> 24);
    }

    private static int getInt(byte[] buf, int pos) {
        return SMB2Buf.getInt(buf, pos);
    }
}
