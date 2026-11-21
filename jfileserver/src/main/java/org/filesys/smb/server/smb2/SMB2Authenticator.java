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

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.filesys.server.auth.ISMBAuthenticator;
import org.filesys.server.auth.SMBAuthenticator;
import org.filesys.server.auth.UserAccount;

/**
 * Handles the security token exchange of an SMB2 session setup, either raw NTLMSSP or NTLMSSP wrapped in SPNEGO.
 */
public final class SMB2Authenticator {

    /**
     * Per session authentication state
     */
    public static final class Context {
        private final NTLMSSPServer m_ntlm = new NTLMSSPServer();

        // DER encoded mechanism list from the client's NegTokenInit, used for the mechListMIC
        private byte[] m_mechTypes;
        private boolean m_spnego;

        // Reason for the last failure, for diagnostics
        private String m_failReason;

        public String getFailureReason() {
            return m_failReason;
        }

        public NTLMSSPServer getNTLM() {
            return m_ntlm;
        }
    }

    /**
     * Result of processing a security token
     */
    public static final class Outcome {
        public final NTLMSSPServer.Result result;
        public final byte[] responseToken;

        Outcome(NTLMSSPServer.Result result, byte[] responseToken) {
            this.result = result;
            this.responseToken = responseToken;
        }
    }

    private static final Outcome FAILED = new Outcome(NTLMSSPServer.Result.FAILED, null);

    private SMB2Authenticator() {
    }

    /**
     * Return the security blob for the negotiate response
     *
     * @return byte[]
     */
    public static byte[] getNegotiateToken() {
        return SPNEGOToken.buildServerInit();
    }

    /**
     * Create an account source that looks up users via the server's authenticator configuration
     *
     * @param auth ISMBAuthenticator
     * @return AccountSource
     */
    public static NTLMSSPServer.AccountSource accountSource(final ISMBAuthenticator auth) {
        return new NTLMSSPServer.AccountSource() {
            @Override
            public byte[] getNTHash(String userName) {
                if (!(auth instanceof SMBAuthenticator))
                    return null;

                UserAccount account = null;
                try {
                    account = ((SMBAuthenticator) auth).getUserDetails(userName);
                }
                catch (RuntimeException ex) {
                    // No users interface configured
                }

                if (account == null)
                    return null;
                if (account.hasMD4Password())
                    return account.getMD4Password();
                if (account.getPassword() == null)
                    return null;

                byte[] ntHash = NTLMSSPServer.ntHash(account.getPassword());
                account.setMD4Password(ntHash);
                return ntHash;
            }
        };
    }

    /**
     * Check if the server allows guest access
     *
     * @param auth ISMBAuthenticator
     * @return boolean
     */
    public static boolean isGuestAllowed(ISMBAuthenticator auth) {
        return auth instanceof SMBAuthenticator && ((SMBAuthenticator) auth).allowGuest();
    }

    /**
     * Process a security token received in a session setup request
     *
     * @param ctx        Context
     * @param token      byte[]
     * @param serverName String
     * @param accounts   AccountSource
     * @return Outcome
     */
    public static Outcome process(Context ctx, byte[] token, String serverName, NTLMSSPServer.AccountSource accounts) {
        try {
            if (NTLMSSPServer.isNTLMSSP(token))
                return processNTLM(ctx, token, serverName, accounts, null);

            if (SPNEGOToken.isInitToken(token, 0, token.length)) {
                SPNEGOToken.Init init = SPNEGOToken.parseInit(token, 0, token.length);
                if (!init.hasMech(SPNEGOToken.OID_NTLMSSP)) {
                    ctx.m_failReason = "client does not offer NTLMSSP";
                    return FAILED;
                }

                ctx.m_spnego = true;
                ctx.m_mechTypes = init.mechTypes;

                // Use the optimistic token if it is for our mechanism, otherwise ask the client to restart the
                // exchange using NTLMSSP
                if (init.isFirstMech(SPNEGOToken.OID_NTLMSSP) && NTLMSSPServer.isNTLMSSP(init.mechToken)
                        && NTLMSSPServer.messageType(init.mechToken) == NTLMSSPServer.TYPE_NEGOTIATE) {
                    byte[] challenge = ctx.m_ntlm.processNegotiate(init.mechToken, serverName);
                    return new Outcome(NTLMSSPServer.Result.CHALLENGE, SPNEGOToken.buildResp(
                            SPNEGOToken.ACCEPT_INCOMPLETE, SPNEGOToken.OID_NTLMSSP, challenge, null));
                }

                return new Outcome(NTLMSSPServer.Result.CHALLENGE, SPNEGOToken.buildResp(
                        SPNEGOToken.ACCEPT_INCOMPLETE, SPNEGOToken.OID_NTLMSSP, null, null));
            }

            if (SPNEGOToken.isRespToken(token, 0, token.length) && ctx.m_spnego) {
                SPNEGOToken.Resp resp = SPNEGOToken.parseResp(token, 0, token.length);
                if (!NTLMSSPServer.isNTLMSSP(resp.responseToken)) {
                    ctx.m_failReason = "SPNEGO response does not contain an NTLMSSP token";
                    return FAILED;
                }
                return processNTLM(ctx, resp.responseToken, serverName, accounts, resp);
            }
        }
        catch (IOException ex) {
            ctx.m_failReason = "malformed security token, " + ex.getMessage();
            return FAILED;
        }
        catch (GeneralSecurityException ex) {
            ctx.m_failReason = "crypto failure, " + ex.getMessage();
            return FAILED;
        }
        catch (RuntimeException ex) {
            ctx.m_failReason = "malformed security token, " + ex;
            return FAILED;
        }

        ctx.m_failReason = "unrecognised security token";
        return FAILED;
    }

    /**
     * Process an NTLMSSP message
     *
     * @param ctx        Context
     * @param token      byte[]
     * @param serverName String
     * @param accounts   AccountSource
     * @param spnegoResp NegTokenResp that carried the message, or null if raw NTLMSSP is being used
     * @return Outcome
     * @exception GeneralSecurityException Crypto error
     */
    private static Outcome processNTLM(Context ctx, byte[] token, String serverName, NTLMSSPServer.AccountSource accounts,
                                       SPNEGOToken.Resp spnegoResp)
            throws GeneralSecurityException {
        NTLMSSPServer ntlm = ctx.m_ntlm;
        int msgType = NTLMSSPServer.messageType(token);

        if (msgType == NTLMSSPServer.TYPE_NEGOTIATE) {
            byte[] challenge = ntlm.processNegotiate(token, serverName);
            if (ctx.m_spnego)
                challenge = SPNEGOToken.buildResp(SPNEGOToken.ACCEPT_INCOMPLETE, null, challenge, null);
            return new Outcome(NTLMSSPServer.Result.CHALLENGE, challenge);
        }

        if (msgType != NTLMSSPServer.TYPE_AUTHENTICATE || !ntlm.hasChallenge()) {
            ctx.m_failReason = "unexpected NTLMSSP message type " + msgType;
            return FAILED;
        }

        NTLMSSPServer.Result result = ntlm.processAuthenticate(token, accounts);
        if (result == NTLMSSPServer.Result.FAILED) {
            ctx.m_failReason = ntlm.getFailureReason();
            return FAILED;
        }

        byte[] respToken = null;

        if (ctx.m_spnego) {
            byte[] mechListMIC = null;

            // If the client protected the mechanism list then verify it, and return our own MIC
            if (result == NTLMSSPServer.Result.AUTHENTICATED && spnegoResp != null && spnegoResp.mechListMIC != null
                    && ctx.m_mechTypes != null && ntlm.canSign()) {
                if (!ntlm.verify(ctx.m_mechTypes, spnegoResp.mechListMIC)) {
                    ctx.m_failReason = "invalid SPNEGO mechListMIC";
                    return FAILED;
                }
                mechListMIC = ntlm.sign(ctx.m_mechTypes);
            }

            respToken = SPNEGOToken.buildResp(SPNEGOToken.ACCEPT_COMPLETED, null, null, mechListMIC);
        }

        return new Outcome(result, respToken);
    }
}
