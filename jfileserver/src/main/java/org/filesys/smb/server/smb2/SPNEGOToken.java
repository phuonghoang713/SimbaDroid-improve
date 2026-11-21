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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Minimal SPNEGO (RFC 4178) token encoder/decoder.
 *
 * <p>Only the parts of the negotiation that are needed to carry NTLMSSP are implemented. The raw DER encoding of the
 * client's mechanism list is preserved as it is required to calculate the mechListMIC.
 */
public final class SPNEGOToken {

    public static final byte[] OID_SPNEGO = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
    public static final byte[] OID_NTLMSSP = {0x2b, 0x06, 0x01, 0x04, 0x01, (byte) 0x82, 0x37, 0x02, 0x02, 0x0a};

    public static final int ACCEPT_COMPLETED = 0;
    public static final int ACCEPT_INCOMPLETE = 1;
    public static final int REJECT = 2;
    public static final int REQUEST_MIC = 3;

    private static final int TAG_OID = 0x06;
    private static final int TAG_OCTET_STRING = 0x04;
    private static final int TAG_ENUMERATED = 0x0A;
    private static final int TAG_GENERAL_STRING = 0x1B;
    private static final int TAG_SEQUENCE = 0x30;
    private static final int TAG_APPLICATION_0 = 0x60;

    private static final String NEG_HINT = "not_defined_in_RFC4178@please_ignore";

    private SPNEGOToken() {
    }

    /**
     * Decoded NegTokenInit
     */
    public static final class Init {
        /** DER encoding of the MechTypeList sequence, as sent by the client */
        public byte[] mechTypes;
        public final List<byte[]> mechOids = new ArrayList<byte[]>();
        public byte[] mechToken;

        public boolean hasMech(byte[] oid) {
            for (byte[] mech : mechOids) {
                if (Arrays.equals(mech, oid))
                    return true;
            }
            return false;
        }

        public boolean isFirstMech(byte[] oid) {
            return !mechOids.isEmpty() && Arrays.equals(mechOids.get(0), oid);
        }
    }

    /**
     * Decoded NegTokenResp
     */
    public static final class Resp {
        public int negState = -1;
        public byte[] supportedMech;
        public byte[] responseToken;
        public byte[] mechListMIC;
    }

    /**
     * DER TLV reader
     */
    private static final class Der {
        private final byte[] buf;
        private int pos;
        private final int end;

        int tag;
        int len;
        int valOff;

        Der(byte[] buf, int off, int end) {
            this.buf = buf;
            this.pos = off;
            this.end = end;
        }

        boolean hasMore() {
            return pos < end;
        }

        void next() throws IOException {
            if (pos + 2 > end)
                throw new IOException("Truncated DER object");

            tag = buf[pos++] & 0xFF;
            int l = buf[pos++] & 0xFF;

            if (l >= 0x80) {
                int cnt = l & 0x7F;
                if (cnt == 0 || cnt > 3 || pos + cnt > end)
                    throw new IOException("Invalid DER length");
                l = 0;
                while (cnt-- > 0)
                    l = (l << 8) | (buf[pos++] & 0xFF);
            }

            if (l > end - pos)
                throw new IOException("DER object overruns buffer");

            len = l;
            valOff = pos;
            pos += l;
        }

        Der sub() {
            return new Der(buf, valOff, valOff + len);
        }

        byte[] value() {
            return Arrays.copyOfRange(buf, valOff, valOff + len);
        }
    }

    /**
     * Check if a security blob is an SPNEGO NegTokenInit
     *
     * @param buf byte[]
     * @param off int
     * @param len int
     * @return boolean
     */
    public static boolean isInitToken(byte[] buf, int off, int len) {
        return len > 0 && (buf[off] & 0xFF) == TAG_APPLICATION_0;
    }

    /**
     * Check if a security blob is an SPNEGO NegTokenResp
     *
     * @param buf byte[]
     * @param off int
     * @param len int
     * @return boolean
     */
    public static boolean isRespToken(byte[] buf, int off, int len) {
        return len > 0 && (buf[off] & 0xFF) == 0xA1;
    }

    /**
     * Parse a GSS-API wrapped NegTokenInit
     *
     * @param buf byte[]
     * @param off int
     * @param len int
     * @return Init
     * @exception IOException Invalid token
     */
    public static Init parseInit(byte[] buf, int off, int len)
            throws IOException {
        Der der = new Der(buf, off, off + len);
        der.next();
        if (der.tag != TAG_APPLICATION_0)
            throw new IOException("Not a GSS-API token");

        Der app = der.sub();
        app.next();
        if (app.tag != TAG_OID || !Arrays.equals(app.value(), OID_SPNEGO))
            throw new IOException("Not an SPNEGO token");

        app.next();
        if (app.tag != 0xA0)
            throw new IOException("Not a NegTokenInit");

        Der choice = app.sub();
        choice.next();
        if (choice.tag != TAG_SEQUENCE)
            throw new IOException("Invalid NegTokenInit");

        Init init = new Init();
        Der seq = choice.sub();

        while (seq.hasMore()) {
            seq.next();

            if (seq.tag == 0xA0) {
                // mechTypes
                Der mechTypes = seq.sub();
                int start = mechTypes.pos;
                mechTypes.next();
                if (mechTypes.tag != TAG_SEQUENCE)
                    throw new IOException("Invalid mechTypes");
                init.mechTypes = Arrays.copyOfRange(buf, start, mechTypes.pos);

                Der oids = mechTypes.sub();
                while (oids.hasMore()) {
                    oids.next();
                    if (oids.tag == TAG_OID)
                        init.mechOids.add(oids.value());
                }
            }
            else if (seq.tag == 0xA2) {
                // mechToken
                Der tok = seq.sub();
                tok.next();
                if (tok.tag != TAG_OCTET_STRING)
                    throw new IOException("Invalid mechToken");
                init.mechToken = tok.value();
            }
        }

        if (init.mechTypes == null)
            throw new IOException("No mechTypes in NegTokenInit");

        return init;
    }

    /**
     * Parse a NegTokenResp
     *
     * @param buf byte[]
     * @param off int
     * @param len int
     * @return Resp
     * @exception IOException Invalid token
     */
    public static Resp parseResp(byte[] buf, int off, int len)
            throws IOException {
        Der der = new Der(buf, off, off + len);
        der.next();
        if (der.tag != 0xA1)
            throw new IOException("Not a NegTokenResp");

        Der choice = der.sub();
        choice.next();
        if (choice.tag != TAG_SEQUENCE)
            throw new IOException("Invalid NegTokenResp");

        Resp resp = new Resp();
        Der seq = choice.sub();

        while (seq.hasMore()) {
            seq.next();
            Der val = seq.sub();

            switch (seq.tag) {
                case 0xA0:
                    val.next();
                    if (val.tag == TAG_ENUMERATED && val.len == 1)
                        resp.negState = buf[val.valOff] & 0xFF;
                    break;
                case 0xA1:
                    val.next();
                    if (val.tag == TAG_OID)
                        resp.supportedMech = val.value();
                    break;
                case 0xA2:
                    val.next();
                    if (val.tag != TAG_OCTET_STRING)
                        throw new IOException("Invalid responseToken");
                    resp.responseToken = val.value();
                    break;
                case 0xA3:
                    val.next();
                    if (val.tag != TAG_OCTET_STRING)
                        throw new IOException("Invalid mechListMIC");
                    resp.mechListMIC = val.value();
                    break;
                default:
                    break;
            }
        }

        return resp;
    }

    /**
     * Build the NegTokenInit2 returned in the SMB2 negotiate response, offering NTLMSSP only
     *
     * @return byte[]
     */
    public static byte[] buildServerInit() {
        byte[] mechTypes = tlv(0xA0, tlv(TAG_SEQUENCE, tlv(TAG_OID, OID_NTLMSSP)));
        byte[] negHints = tlv(0xA3, tlv(TAG_SEQUENCE,
                tlv(0xA0, tlv(TAG_GENERAL_STRING, NEG_HINT.getBytes(StandardCharsets.US_ASCII)))));
        byte[] negTokenInit = tlv(0xA0, tlv(TAG_SEQUENCE, mechTypes, negHints));

        return tlv(TAG_APPLICATION_0, tlv(TAG_OID, OID_SPNEGO), negTokenInit);
    }

    /**
     * Build a NegTokenResp
     *
     * @param negState      int
     * @param supportedMech byte[] or null
     * @param responseToken byte[] or null
     * @param mechListMIC   byte[] or null
     * @return byte[]
     */
    public static byte[] buildResp(int negState, byte[] supportedMech, byte[] responseToken, byte[] mechListMIC) {
        List<byte[]> parts = new ArrayList<byte[]>(4);

        parts.add(tlv(0xA0, tlv(TAG_ENUMERATED, new byte[]{(byte) negState})));
        if (supportedMech != null)
            parts.add(tlv(0xA1, tlv(TAG_OID, supportedMech)));
        if (responseToken != null)
            parts.add(tlv(0xA2, tlv(TAG_OCTET_STRING, responseToken)));
        if (mechListMIC != null)
            parts.add(tlv(0xA3, tlv(TAG_OCTET_STRING, mechListMIC)));

        return tlv(0xA1, tlv(TAG_SEQUENCE, parts.toArray(new byte[parts.size()][])));
    }

    /**
     * Encode a DER tag/length/value from one or more value parts
     *
     * @param tag   int
     * @param parts byte[][]
     * @return byte[]
     */
    private static byte[] tlv(int tag, byte[]... parts) {
        int len = 0;
        for (byte[] part : parts)
            len += part.length;

        ByteArrayOutputStream out = new ByteArrayOutputStream(len + 6);
        out.write(tag);

        if (len < 0x80)
            out.write(len);
        else if (len < 0x100) {
            out.write(0x81);
            out.write(len);
        }
        else if (len < 0x10000) {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len);
        }
        else {
            out.write(0x83);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        }

        for (byte[] part : parts)
            out.write(part, 0, part.length);

        return out.toByteArray();
    }
}
