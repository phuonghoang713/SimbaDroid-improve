/*
        Copyright 2023 worstperson

        Licensed under the Apache License, Version 2.0 (the "License");
        you may not use this file except in compliance with the License.
        You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

        Unless required by applicable law or agreed to in writing, software
        distributed under the License is distributed on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
        See the License for the specific language governing permissions and
        limitations under the License.

        This file modified by Jan Henning, 2024
*/

// This code based on https://github.com/worstperson/USBTether/blob/d7da44d67ffd72501bed707714a91ad5f02deff6/app/src/main/java/com/worstperson/usbtether/Script.java

package de.buttercookie.simbadroid.util;

import android.util.Log;

import com.topjohnwu.superuser.Shell;

public class Iptables {
    private static final String LOGTAG = "Iptables";

    private static String hasWait;

    private Iptables() {}

    private static boolean shellCommand(String command) {
        Shell.Result result = Shell.cmd(command).exec();
        for (String message : result.getOut()) {
            Log.i(LOGTAG, message);
        }
        return result.isSuccess();
    }

    private static String waitCmd() {
        if (hasWait == null) {
            hasWait = testWait();
        }
        return hasWait;
    }

    private static String testWait() {
        String cmd = "";
        if (shellCommand("iptables -w 0 --help > /dev/null")) {
            cmd = "-w 2 ";
        } else if (shellCommand("iptables -w --help > /dev/null")) { // Early versions do not have the timeout
            cmd = "-w ";
        }
        return cmd;
    }

    /**
     * Run an iptables command. Must not be called on the main thread, as starting the root shell and running
     * commands in it can block for a long time.
     *
     * @return Whether the rule is in the requested state afterwards, i.e. present after adding it and no longer
     * present after removing it.
     */
    public static boolean iptables(boolean isIPv6, String table, String operation, String rule) {
        String command = isIPv6 ? "ip6tables" : "iptables";
        boolean adding = operation.equals("N") || operation.equals("I") || operation.equals("A");
        boolean exists = Shell.cmd(command + " " + waitCmd() + "-t " + table + " -C " + rule).exec().isSuccess();
        if (exists == adding) {
            // Nothing to do
            return true;
        }
        return shellCommand(command + " " + waitCmd() + "-t " + table + " -" + operation + " " + rule);
    }

    /**
     * Check whether a root shell is available. This starts the shell if necessary, which may show the
     * superuser prompt and can take a long time, so it must not be called on the main thread.
     */
    public static boolean hasRoot() {
        try {
            return Shell.getShell().isRoot();
        } catch (Exception e) {
            Log.i(LOGTAG, "No root shell available", e);
            return false;
        }
    }
}
