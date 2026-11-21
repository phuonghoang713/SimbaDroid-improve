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
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.MD4Digest;

/**
 * Server side of an NTLMSSP authentication exchange, see [MS-NLMP].
 *
 * <p>Supports NTLMv2 authentication against a known NT hash, anonymous logons, and reports unknown users so that the
 * caller can map them to a guest logon. The exported session key is made available for SMB2 signing/encryption, and
 * NTLMSSP message signing is implemented for the SPNEGO mechListMIC.
 */
public final class NTLMSSPServer {

    /**
     * Source of account credentials
     */
    public interface AccountSource {

        /**
         * Return the NT hash (MD4 of the UTF-16LE password) for a user
         *
         * @param userName String
         * @return byte[] 16 byte NT hash, or null if the user is not known
         */
        byte[] getNTHash(String userName);
    }

    public enum Result {
        /** A challenge has been generated, another round is required */
        CHALLENGE,
        /** The user has been authenticated, a session key is available */
        AUTHENTICATED,
        /** An anonymous logon was requested */
        ANONYMOUS,
        /** The user is not known, the caller may map this to a guest logon */
        UNKNOWN_USER,
        /** Authentication failed */
        FAILED
    }

    // Message types
    public static final int TYPE_NEGOTIATE = 1;
    public static final int TYPE_CHALLENGE = 2;
    public static final int TYPE_AUTHENTICATE = 3;

    // Negotiate flags
    private static final int FLG_UNICODE = 0x00000001;
    private static final int FLG_REQUEST_TARGET = 0x00000004;
    private static final int FLG_SIGN = 0x00000010;
    private static final int FLG_SEAL = 0x00000020;
    private static final int FLG_NTLM = 0x00000200;
    private static final int FLG_ALWAYS_SIGN = 0x00008000;
    private static final int FLG_TARGET_TYPE_SERVER = 0x00020000;
    private static final int FLG_EXTENDED_SECURITY = 0x00080000;
    private static final int FLG_TARGET_INFO = 0x00800000;
    private static final int FLG_VERSION = 0x02000000;
    private static final int FLG_128BIT = 0x20000000;
    private static final int FLG_KEY_EXCH = 0x40000000;
    private static final int FLG_56BIT = 0x80000000;

    // AV pair ids
    private static final int AV_EOL = 0;
    private static final int AV_NB_COMPUTER = 1;
    private static final int AV_NB_DOMAIN = 2;
    private static final int AV_DNS_COMPUTER = 3;
    private static final int AV_DNS_DOMAIN = 4;
    private static final int AV_FLAGS = 6;
    private static final int AV_TIMESTAMP = 7;

    private static final int AV_FLAG_MIC_PRESENT = 0x00000002;

    private static final byte[] SIGNATURE = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

    // Offset of the MIC in an authenticate message that includes the version field
    private static final int MIC_OFFSET = 72;
    private static final int MIC_LEN = 16;

    // Offset of the AV pairs within the NTLMv2 client challenge structure, following the 16 byte NTProofStr
    private static final int NTLMV2_AVPAIRS_OFFSET = 16 + 28;

    private static final byte[] MAGIC_CLIENT_SIGN = magic("session key to client-to-server signing key magic constant");
    private static final byte[] MAGIC_SERVER_SIGN = magic("session key to server-to-client signing key magic constant");
    private static final byte[] MAGIC_CLIENT_SEAL = magic("session key to client-to-server sealing key magic constant");
    private static final byte[] MAGIC_SERVER_SEAL = magic("session key to server-to-client sealing key magic constant");

    // Windows 10 version block, NTLM revision 15
    private static final byte[] VERSION = {0x0A, 0x00, 0x61, 0x4A, 0x00, 0x00, 0x00, 0x0F};

    private static final long NT_TIME_OFFSET = 116444736000000000L;

    private byte[] m_negotiateMsg;
    private byte[] m_challengeMsg;
    private byte[] m_challenge;

    private int m_flags;
    private String m_userName = "";
    private String m_domain = "";
    private String m_workstation = "";

    private byte[] m_sessionKey;

    // Reason for an authentication failure, for diagnostics. Never contains secrets.
    private String m_failReason;

    public String getFailureReason() {
        return m_failReason;
    }

    private Result fail(String reason) {
        m_failReason = reason;
        return Result.FAILED;
    }

    private static byte[] magic(String str) {
        byte[] ascii = str.getBytes(StandardCharsets.US_ASCII);
        return Arrays.copyOf(ascii, ascii.length + 1);
    }

    /**
     * Check if a token is an NTLMSSP message
     *
     * @param tok byte[]
     * @return boolean
     */
    public static boolean isNTLMSSP(byte[] tok) {
        if (tok == null || tok.length < 12)
            return false;
        for (int i = 0; i < SIGNATURE.length; i++) {
            if (tok[i] != SIGNATURE[i])
                return false;
        }
        return true;
    }

    /**
     * Return the NTLMSSP message type, the token must have been checked using isNTLMSSP()
     *
     * @param tok byte[]
     * @return int
     */
    public static int messageType(byte[] tok) {
        return SMB2Buf.getInt(tok, 8);
    }

    public String getUserName() {
        return m_userName;
    }

    public String getDomain() {
        return m_domain;
    }

    public String getWorkstation() {
        return m_workstation;
    }

    /**
     * Return the exported session key, only valid after a successful authentication
     *
     * @return byte[]
     */
    public byte[] getSessionKey() {
        return m_sessionKey;
    }

    /**
     * Check if a challenge has been issued, ie. an authenticate message can be processed
     *
     * @return boolean
     */
    public boolean hasChallenge() {
        return m_challenge != null;
    }

    /**
     * Check if NTLMSSP message signing is available
     *
     * @return boolean
     */
    public boolean canSign() {
        return m_sessionKey != null && (m_flags & FLG_EXTENDED_SECURITY) != 0;
    }

    /**
     * Process a negotiate (type 1) message and generate the challenge (type 2) message
     *
     * @param negotiate  byte[]
     * @param serverName String
     * @return byte[] Challenge message
     */
    public byte[] processNegotiate(byte[] negotiate, String serverName) {
        m_negotiateMsg = negotiate;

        int clientFlags = negotiate.length >= 16 ? SMB2Buf.getInt(negotiate, 12) : 0;

        int flags = FLG_UNICODE | FLG_REQUEST_TARGET | FLG_NTLM | FLG_ALWAYS_SIGN | FLG_TARGET_TYPE_SERVER
                | FLG_EXTENDED_SECURITY | FLG_TARGET_INFO | FLG_VERSION;
        flags |= clientFlags & (FLG_SIGN | FLG_SEAL | FLG_128BIT | FLG_KEY_EXCH | FLG_56BIT);

        m_challenge = SMB2Crypto.randomBytes(8);

        String nbName = serverName.toUpperCase(Locale.ROOT);
        String dnsName = serverName.toLowerCase(Locale.ROOT);

        byte[] targetName = nbName.getBytes(StandardCharsets.UTF_16LE);

        SMB2Buf info = new SMB2Buf(256);
        putAvPair(info, AV_NB_DOMAIN, nbName.getBytes(StandardCharsets.UTF_16LE));
        putAvPair(info, AV_NB_COMPUTER, nbName.getBytes(StandardCharsets.UTF_16LE));
        putAvPair(info, AV_DNS_DOMAIN, dnsName.getBytes(StandardCharsets.UTF_16LE));
        putAvPair(info, AV_DNS_COMPUTER, dnsName.getBytes(StandardCharsets.UTF_16LE));

        byte[] timestamp = new byte[8];
        long ntTime = System.currentTimeMillis() * 10000L + NT_TIME_OFFSET;
        for (int i = 0; i < 8; i++)
            timestamp[i] = (byte) (ntTime >>> (8 * i));
        putAvPair(info, AV_TIMESTAMP, timestamp);
        putAvPair(info, AV_EOL, new byte[0]);

        int infoLen = info.position();
        int payloadOff = 56;

        SMB2Buf msg = new SMB2Buf(payloadOff + targetName.length + infoLen);
        msg.putBytes(SIGNATURE);
        msg.putInt(TYPE_CHALLENGE);
        msg.putShort(targetName.length);
        msg.putShort(targetName.length);
        msg.putInt(payloadOff);
        msg.putInt(flags);
        msg.putBytes(m_challenge);
        msg.putZeros(8);
        msg.putShort(infoLen);
        msg.putShort(infoLen);
        msg.putInt(payloadOff + targetName.length);
        msg.putBytes(VERSION);
        msg.putBytes(targetName);
        msg.putBytes(info.array(), 0, infoLen);

        m_challengeMsg = Arrays.copyOf(msg.array(), msg.position());
        return m_challengeMsg;
    }

    private static void putAvPair(SMB2Buf buf, int id, byte[] value) {
        buf.putShort(id);
        buf.putShort(value.length);
        buf.putBytes(value);
    }

    /**
     * Process an authenticate (type 3) message
     *
     * @param auth     byte[]
     * @param accounts AccountSource
     * @return Result
     */
    public Result processAuthenticate(byte[] auth, AccountSource accounts) {
        m_sessionKey = null;

        if (m_challenge == null || auth.length < 64)
            return fail("authenticate message too short or no challenge issued");

        try {
            byte[] ntResponse = securityBuffer(auth, 20);
            byte[] domain = securityBuffer(auth, 28);
            byte[] user = securityBuffer(auth, 36);
            byte[] workstation = securityBuffer(auth, 44);
            byte[] encSessionKey = securityBuffer(auth, 52);

            if (ntResponse == null || domain == null || user == null || workstation == null || encSessionKey == null)
                return fail("invalid field in authenticate message");

            m_flags = SMB2Buf.getInt(auth, 60);

            boolean unicode = (m_flags & FLG_UNICODE) != 0;
            m_userName = decodeString(user, unicode);
            m_domain = decodeString(domain, unicode);
            m_workstation = decodeString(workstation, unicode);

            // Anonymous logon
            if (m_userName.isEmpty() && ntResponse.length == 0)
                return Result.ANONYMOUS;

            byte[] ntHash = accounts.getNTHash(m_userName);
            if (ntHash == null)
                return Result.UNKNOWN_USER;

            // Only NTLMv2 responses are accepted, the NTLMv1 variants are too weak to be worth supporting
            if (ntResponse.length < NTLMV2_AVPAIRS_OFFSET + 4)
                return fail("not an NTLMv2 response, length " + ntResponse.length);

            byte[] proof = Arrays.copyOf(ntResponse, 16);
            byte[] v2hash = null;

            String upperUser = m_userName.toUpperCase(Locale.ROOT);
            String[] domains = {m_domain, m_domain.toUpperCase(Locale.ROOT), ""};

            for (int i = 0; i < domains.length && v2hash == null; i++) {
                if (i > 0 && domains[i].equals(domains[i - 1]))
                    continue;

                byte[] candidate = hmacMD5(ntHash, (upperUser + domains[i]).getBytes(StandardCharsets.UTF_16LE));

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(candidate, "HmacMD5"));
                mac.update(m_challenge);
                mac.update(ntResponse, 16, ntResponse.length - 16);

                if (MessageDigest.isEqual(mac.doFinal(), proof))
                    v2hash = candidate;
            }

            if (v2hash == null)
                return fail("wrong password");

            // Generate the session key
            byte[] sessionBaseKey = hmacMD5(v2hash, proof);
            byte[] sessionKey = sessionBaseKey;

            if ((m_flags & FLG_KEY_EXCH) != 0) {
                if (encSessionKey.length != 16)
                    return fail("invalid encrypted session key");
                sessionKey = rc4(sessionBaseKey, encSessionKey);
            }

            // Validate the message integrity code, if the client indicates that it is present
            if (hasMIC(ntResponse)) {
                if (auth.length < MIC_OFFSET + MIC_LEN || m_negotiateMsg == null)
                    return fail("message integrity code missing");

                byte[] rxMIC = Arrays.copyOfRange(auth, MIC_OFFSET, MIC_OFFSET + MIC_LEN);
                byte[] authCopy = auth.clone();
                Arrays.fill(authCopy, MIC_OFFSET, MIC_OFFSET + MIC_LEN, (byte) 0);

                Mac mac = Mac.getInstance("HmacMD5");
                mac.init(new SecretKeySpec(sessionKey, "HmacMD5"));
                mac.update(m_negotiateMsg);
                mac.update(m_challengeMsg);
                mac.update(authCopy);

                if (!MessageDigest.isEqual(mac.doFinal(), rxMIC))
                    return fail("invalid message integrity code");
            }

            m_sessionKey = sessionKey;
            return Result.AUTHENTICATED;
        }
        catch (GeneralSecurityException ex) {
            return fail("crypto failure, " + ex.getMessage());
        }
        catch (RuntimeException ex) {
            return fail("malformed authenticate message, " + ex);
        }
    }

    /**
     * Check the AV pairs of an NTLMv2 response to see if the authenticate message carries a MIC
     *
     * @param ntResponse byte[]
     * @return boolean
     */
    private static boolean hasMIC(byte[] ntResponse) {
        int pos = NTLMV2_AVPAIRS_OFFSET;

        while (pos + 4 <= ntResponse.length) {
            int id = SMB2Buf.getShort(ntResponse, pos);
            int len = SMB2Buf.getShort(ntResponse, pos + 2);
            pos += 4;

            if (id == AV_EOL || pos + len > ntResponse.length)
                break;
            if (id == AV_FLAGS && len >= 4)
                return (SMB2Buf.getInt(ntResponse, pos) & AV_FLAG_MIC_PRESENT) != 0;

            pos += len;
        }
        return false;
    }

    /**
     * Generate an NTLMSSP signature for data sent by the server, using sequence number zero
     *
     * @param data byte[]
     * @return byte[] 16 byte signature
     * @exception GeneralSecurityException Crypto error
     */
    public byte[] sign(byte[] data)
            throws GeneralSecurityException {
        return makeSignature(data, MAGIC_SERVER_SIGN, MAGIC_SERVER_SEAL);
    }

    /**
     * Verify an NTLMSSP signature for data sent by the client, using sequence number zero
     *
     * @param data      byte[]
     * @param signature byte[]
     * @return boolean
     * @exception GeneralSecurityException Crypto error
     */
    public boolean verify(byte[] data, byte[] signature)
            throws GeneralSecurityException {
        return MessageDigest.isEqual(makeSignature(data, MAGIC_CLIENT_SIGN, MAGIC_CLIENT_SEAL), signature);
    }

    private byte[] makeSignature(byte[] data, byte[] signMagic, byte[] sealMagic)
            throws GeneralSecurityException {
        if (!canSign())
            throw new GeneralSecurityException("NTLMSSP signing not available");

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(m_sessionKey);
        byte[] signKey = md5.digest(signMagic);

        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(signKey, "HmacMD5"));
        mac.update(new byte[4]);    // sequence number
        byte[] checksum = Arrays.copyOf(mac.doFinal(data), 8);

        if ((m_flags & FLG_KEY_EXCH) != 0) {
            // The checksum is encrypted using the sealing key
            byte[] keyPart = m_sessionKey;
            if ((m_flags & FLG_128BIT) == 0)
                keyPart = Arrays.copyOf(m_sessionKey, (m_flags & FLG_56BIT) != 0 ? 7 : 5);

            md5.reset();
            md5.update(keyPart);
            checksum = rc4(md5.digest(sealMagic), checksum);
        }

        byte[] sig = new byte[16];
        sig[0] = 1;     // version
        System.arraycopy(checksum, 0, sig, 4, 8);
        return sig;
    }

    /**
     * Calculate the NT hash of a password
     *
     * @param password String
     * @return byte[]
     */
    public static byte[] ntHash(String password) {
        byte[] pwd = password.getBytes(StandardCharsets.UTF_16LE);
        MD4Digest md4 = new MD4Digest();
        md4.update(pwd, 0, pwd.length);
        byte[] hash = new byte[md4.getDigestSize()];
        md4.doFinal(hash, 0);
        return hash;
    }

    private static byte[] hmacMD5(byte[] key, byte[] data)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(new SecretKeySpec(key, "HmacMD5"));
        return mac.doFinal(data);
    }

    /**
     * RC4, implemented locally as the cipher is not available from all JCE providers
     *
     * @param key  byte[]
     * @param data byte[]
     * @return byte[]
     */
    private static byte[] rc4(byte[] key, byte[] data) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++)
            s[i] = i;

        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
        }

        byte[] out = new byte[data.length];
        int i = 0;
        j = 0;
        for (int k = 0; k < data.length; k++) {
            i = (i + 1) & 0xFF;
            j = (j + s[i]) & 0xFF;
            int t = s[i];
            s[i] = s[j];
            s[j] = t;
            out[k] = (byte) (data[k] ^ s[(s[i] + s[j]) & 0xFF]);
        }
        return out;
    }

    /**
     * Extract a security buffer (length, max length, offset) field from an NTLMSSP message
     *
     * @param msg      byte[]
     * @param fieldOff int
     * @return byte[] or null if the field is not valid
     */
    private static byte[] securityBuffer(byte[] msg, int fieldOff) {
        int len = SMB2Buf.getShort(msg, fieldOff);
        int off = SMB2Buf.getInt(msg, fieldOff + 4);

        if (len == 0)
            return new byte[0];
        if (off < 0 || off > msg.length || len > msg.length - off)
            return null;
        return Arrays.copyOfRange(msg, off, off + len);
    }

    private static String decodeString(byte[] byts, boolean unicode) {
        return new String(byts, unicode ? StandardCharsets.UTF_16LE : StandardCharsets.ISO_8859_1);
    }
}
