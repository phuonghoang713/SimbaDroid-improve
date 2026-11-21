/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package de.buttercookie.simbadroid;

import static de.buttercookie.simbadroid.util.StyledTextUtils.getStyledText;

import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.text.Editable;
import android.text.TextUtils;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.textfield.TextInputEditText;

import org.apache.commons.lang3.StringUtils;

import de.buttercookie.simbadroid.databinding.ActivityMainBinding;
import de.buttercookie.simbadroid.databinding.DialogSettingsBinding;
import de.buttercookie.simbadroid.permissions.Permissions;
import de.buttercookie.simbadroid.service.SmbService;
import de.buttercookie.simbadroid.service.SmbServiceConnection;
import de.buttercookie.simbadroid.service.SmbServiceStatusLiveData;
import de.buttercookie.simbadroid.settings.ServerSettings;

public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
    private SmbService mService;
    private boolean mBound = false;
    private AlertDialog mSettingsDialog;

    private final SmbServiceConnection mSmbSrvConn = new SmbServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            super.onServiceConnected(name, service);
            mService = getService();
            mBound = true;
            // The state of the button depends on being connected to the service, and the current status has
            // normally been delivered before the connection is established.
            refreshStatus();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            super.onServiceDisconnected(name);
            mBound = false;
            mService = null;
            refreshStatus();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        binding.toggleService.setOnClickListener(v -> toggleSmbService());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            binding.toggleService.setAllowClickWhenDisabled(true);
        }
        binding.openSettings.setOnClickListener(v -> showSettingsDialog());

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        SmbServiceStatusLiveData.get().observe(this, status -> {
            updateButtonState(status);
            updateStatusText(status);
        });
    }

    @Override
    protected void onStart() {
        super.onStart();
        Intent serviceIntent = new Intent(this, SmbService.class);
        bindService(serviceIntent, mSmbSrvConn, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onStop() {
        super.onStop();
        unbindService(mSmbSrvConn);
        mBound = false;
        mService = null;
    }

    @Override
    protected void onDestroy() {
        if (mSettingsDialog != null) {
            mSettingsDialog.dismiss();
            mSettingsDialog = null;
        }
        super.onDestroy();
    }

    private void refreshStatus() {
        SmbService.Status status = SmbServiceStatusLiveData.get().getValue();
        if (status != null) {
            updateButtonState(status);
            updateStatusText(status);
        }
    }

    private void updateButtonState(SmbService.Status status) {
        final MaterialButton button = binding.toggleService;
        if (status.serviceRunning()) {
            button.setText(R.string.button_stop_server);
            button.setIcon(AppCompatResources.getDrawable(this, R.drawable.ic_stop));
            button.setEnabled(true);
        } else {
            button.setText(R.string.button_start_server);
            button.setIcon(AppCompatResources.getDrawable(this, R.drawable.ic_start));
            button.setEnabled(mBound && mService != null && mService.isNetworkAvailable());
        }
    }

    private void updateStatusText(SmbService.Status status) {
        final TextView statusText = binding.serviceStatus;
        if (!status.serviceRunning()) {
            statusText.setText(TextUtils.concat(getText(R.string.status_server_off), "\n\n",
                    getAccessText(ServerSettings.load(this))));
        } else if (!status.serverRunning()) {
            statusText.setText(R.string.message_server_waiting_network);
        } else if (StringUtils.isBlank(status.ipAddress())) {
            statusText.setText(R.string.message_server_running);
        } else {
            statusText.setText(TextUtils.concat(getAddressText(status), "\n\n",
                    status.userName() != null ?
                            getStyledText(this, R.string.status_access_login, status.userName()) :
                            getText(R.string.status_access_open)));
        }
    }

    /**
     * Describe how the server can be reached.
     */
    private CharSequence getAddressText(SmbService.Status status) {
        if (status.standardPort()) {
            // The server is reachable on the standard SMB port, so clients just need its name or address
            if (StringUtils.isBlank(status.mdnsAddress())) {
                return getStyledText(this, R.string.status_server_running_ip, status.ipUncAddress());
            }
            return getStyledText(this, R.string.status_server_running,
                    status.mdnsAddress(), status.netBiosAddress(), status.ipUncAddress());
        }

        // Without root the standard port isn't available, so clients need to be told which port to use
        CharSequence text = getStyledText(this, R.string.status_server_running_port,
                status.ipAddress(), status.port());
        if (!StringUtils.isBlank(status.mdnsHost())) {
            text = TextUtils.concat(text, "\n",
                    getStyledText(this, R.string.status_server_running_name, status.mdnsHost()));
        }
        return TextUtils.concat(text, "\n\n",
                getStyledText(this, R.string.status_port_hint, status.port(), status.ipAddress()));
    }

    private CharSequence getAccessText(ServerSettings settings) {
        return settings.hasCredentials() ?
                getStyledText(this, R.string.status_access_login, settings.getUserName()) :
                getText(R.string.status_access_open);
    }

    private void toggleSmbService() {
        if (!mBound || mService == null) {
            Toast.makeText(this,
                    R.string.toast_error_starting_server,
                    Toast.LENGTH_SHORT).show();
            return;
        }
        if (!mService.isRunning()) {
            startSmbService();
        } else {
            stopSmbService();
        }
    }

    private void startSmbService() {
        if (!mService.isNetworkAvailable()) {
            Toast.makeText(this,
                    R.string.toast_error_no_network,
                    Toast.LENGTH_SHORT).show();
            return;
        }
        SmbService.startService(this, true);
    }

    private void stopSmbService() {
        mService.stop();
    }

    private void showSettingsDialog() {
        if (mSettingsDialog != null && mSettingsDialog.isShowing()) {
            return;
        }

        final DialogSettingsBinding dialogBinding = DialogSettingsBinding.inflate(getLayoutInflater());
        final ServerSettings current = ServerSettings.load(this);
        dialogBinding.settingsUserName.setText(current.getUserName());
        dialogBinding.settingsPassword.setText(current.getPassword());
        dialogBinding.settingsSmb1.setChecked(current.isSmb1Enabled());

        final AlertDialog dialog = new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.settings_title)
                .setView(dialogBinding.getRoot())
                .setPositiveButton(R.string.settings_save, null)
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        // Handle the button ourselves, so that the dialog stays open if the input isn't valid
        dialog.setOnShowListener(d -> dialog.getButton(DialogInterface.BUTTON_POSITIVE)
                .setOnClickListener(v -> {
                    if (saveSettings(dialogBinding)) {
                        dialog.dismiss();
                    }
                }));
        dialog.setOnDismissListener(d -> {
            if (mSettingsDialog == dialog) {
                mSettingsDialog = null;
            }
        });
        mSettingsDialog = dialog;
        dialog.show();
    }

    /**
     * @return Whether the settings were valid and have been saved.
     */
    private boolean saveSettings(DialogSettingsBinding dialogBinding) {
        final String userName = textOf(dialogBinding.settingsUserName).trim();
        final String password = textOf(dialogBinding.settingsPassword);

        dialogBinding.settingsUserNameLayout.setError(null);
        dialogBinding.settingsPasswordLayout.setError(null);

        // Leaving both fields empty means that no login is required
        if (!userName.isEmpty() || !password.isEmpty()) {
            boolean valid = true;
            if (!ServerSettings.isValidUserName(userName)) {
                dialogBinding.settingsUserNameLayout.setError(
                        getString(R.string.settings_error_user_name));
                valid = false;
            }
            if (!ServerSettings.isValidPassword(password)) {
                dialogBinding.settingsPasswordLayout.setError(
                        getString(R.string.settings_error_password,
                                ServerSettings.MIN_PASSWORD_LENGTH));
                valid = false;
            }
            if (!valid) {
                return false;
            }
        }

        new ServerSettings(userName, password, dialogBinding.settingsSmb1.isChecked()).save(this);

        if (mBound && mService != null && mService.isRunning()) {
            // The settings are only read when the server starts
            Toast.makeText(this, R.string.settings_saved_restart, Toast.LENGTH_LONG).show();
        }
        refreshStatus();
        return true;
    }

    private static String textOf(TextInputEditText editText) {
        Editable text = editText.getText();
        return text != null ? text.toString() : "";
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        Permissions.onRequestPermissionsResult(this, permissions, grantResults);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        // Note that the value identifying the request is the request code - the result code of the system settings
        // screen is always RESULT_CANCELED.
        if (requestCode == Permissions.ACTIVITY_MANAGE_STORAGE_REQUEST_CODE) {
            Permissions.onManageStorageActivityResult(this);
        }
    }
}
