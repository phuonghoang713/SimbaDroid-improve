/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package de.buttercookie.simbadroid.settings;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;

import java.util.regex.Pattern;

/**
 * User configurable settings of the SMB server.
 *
 * <p>The settings are read when the server is started, changes take effect the next time it is started.
 */
public final class ServerSettings {
    /**
     * Name of the preferences file. The file holds the access password, so it is excluded from backups - see
     * res/xml/backup_rules.xml and res/xml/data_extraction_rules.xml.
     */
    public static final String PREFS_NAME = "server_settings";

    private static final String KEY_USER_NAME = "user_name";
    private static final String KEY_PASSWORD = "password";
    private static final String KEY_SMB1_ENABLED = "smb1_enabled";

    public static final int MAX_USER_NAME_LENGTH = 32;
    public static final int MIN_PASSWORD_LENGTH = 6;
    public static final int MAX_PASSWORD_LENGTH = 127;

    // Keep to characters that every SMB client can send without quoting problems
    private static final Pattern VALID_USER_NAME = Pattern.compile("[A-Za-z0-9._-]{1," + MAX_USER_NAME_LENGTH + "}");

    private final String mUserName;
    private final String mPassword;
    private final boolean mSmb1Enabled;

    public ServerSettings(@NonNull String userName, @NonNull String password, boolean smb1Enabled) {
        mUserName = userName;
        mPassword = password;
        mSmb1Enabled = smb1Enabled;
    }

    public static ServerSettings load(@NonNull Context context) {
        SharedPreferences prefs = getPrefs(context);
        return new ServerSettings(
                prefs.getString(KEY_USER_NAME, ""),
                prefs.getString(KEY_PASSWORD, ""),
                // SMB1 stays enabled by default so that existing setups with old clients keep working
                prefs.getBoolean(KEY_SMB1_ENABLED, true));
    }

    public void save(@NonNull Context context) {
        getPrefs(context).edit()
                .putString(KEY_USER_NAME, mUserName)
                .putString(KEY_PASSWORD, mPassword)
                .putBoolean(KEY_SMB1_ENABLED, mSmb1Enabled)
                .apply();
    }

    private static SharedPreferences getPrefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    @NonNull
    public String getUserName() {
        return mUserName;
    }

    @NonNull
    public String getPassword() {
        return mPassword;
    }

    public boolean isSmb1Enabled() {
        return mSmb1Enabled;
    }

    /**
     * @return Whether clients need to log in with the configured user name and password. Without credentials the
     * server is open to everybody on the local network.
     */
    public boolean hasCredentials() {
        return isValidUserName(mUserName) && isValidPassword(mPassword);
    }

    public static boolean isValidUserName(String userName) {
        return userName != null && VALID_USER_NAME.matcher(userName).matches();
    }

    public static boolean isValidPassword(String password) {
        return password != null && password.length() >= MIN_PASSWORD_LENGTH &&
                password.length() <= MAX_PASSWORD_LENGTH;
    }
}
