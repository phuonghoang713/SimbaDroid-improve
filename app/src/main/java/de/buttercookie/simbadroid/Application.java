/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

package de.buttercookie.simbadroid;

import com.topjohnwu.superuser.Shell;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Application extends android.app.Application {
    static {
        // Replace Android's built-in, cut down, BC provider with our own dependency. It is needed for the legacy
        // algorithms used by SMB1 authentication (MD4, DES) that the platform no longer offers.
        //
        // The provider is added at the end of the list, so that the platform's native and hardware accelerated
        // implementations keep being used for everything else. That matters a lot for the throughput of SMB2/3
        // signing and encryption (HMAC-SHA256, AES-CMAC, AES-GCM), which runs on every packet.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());

        Shell.setDefaultBuilder(Shell.Builder.create()
                .setFlags(Shell.FLAG_MOUNT_MASTER));
    }
}
