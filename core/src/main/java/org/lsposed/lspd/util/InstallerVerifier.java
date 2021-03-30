/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2020 EdXposed Contributors
 * Copyright (C) 2021 LSPosed Contributors
 */

package org.lsposed.lspd.util;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Bundle;
import android.os.Handler;
import android.widget.Toast;

import com.android.apksig.ApkVerifier;

import java.io.File;
import java.util.Arrays;
import java.util.Base64;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;

public class InstallerVerifier {

    private static final String Sign = "MIIDhzCCAm+gAwIBAgIEFkhp1DANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJDTjEWMBQGA1UECBMNSmlhbmdzdVN1emhvdTERMA8GA1UEBxMIQ2hhbmdzaHUxFjAUBgNVBAoTDUdvRGFmdFdpdGhFQksxDDAKBgNVBAsTA0FwcDEUMBIGA1UEAxMLS2FpZGkgQ2hhbmcwHhcNMjEwMzI4MDg1MDQxWhcNNDYwMzIyMDg1MDQxWjB0MQswCQYDVQQGEwJDTjEWMBQGA1UECBMNSmlhbmdzdVN1emhvdTERMA8GA1UEBxMIQ2hhbmdzaHUxFjAUBgNVBAoTDUdvRGFmdFdpdGhFQksxDDAKBgNVBAsTA0FwcDEUMBIGA1UEAxMLS2FpZGkgQ2hhbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC90MvjAE02VPErVOnjt9JAgcgHG9mr463+7mKhG4FcoRkVOQtISJ+VR5rKRr5TROuCriN6BmCLMywRZrmJgV//DYStCULNOGCwFlsyg1an/GOI8Xq/O7iSvD+MyoiZYl3bfNAWx1rLBO8cniLn/zZR9s3FuLXxxN86mxuefbvD07e+ITRjRubGAwjyEsdveGpJaZB1QA9YfxD/xYBy71pUAOfv1r49IZEOQR9YbC1FbaWkClyajBm0BWm3wtWMteivMjOJht9iETmmSkM/hhnjy99hBi1YAdSIfsPVO+0dXtjoRmDi+I6PQlwrVgRkRBBEezNrFWwOPj9tvyv9O461AgMBAAGjITAfMB0GA1UdDgQWBBQH9NsAoMRgUvFAXfdG79sE+jzSMTANBgkqhkiG9w0BAQsFAAOCAQEAnp+gOH+CzqkoCv6JY6TxQkCe8vxt/lScOB4II/pVHKLPHMYbN++MsujD+almaN7SMaWryBA9V0TwOH5Tu9z4mcuwdHDvVdMhP0/CPylC7lvSELLmXVZNVJRVSvi3soyckjIz/1GLMCbDi7/4N+AMwk4yXzAEDm+MumK5S+yqFwxhEej03BCZRu+wMGMR8EQd15gq/f4KzEcEmXWCZnhy51FaTjLM1dxOEaXvBYgmNK6GDwLh0m93+mgbjNFcZ9cZ0fgHGlbTfNlzlC6If4jKXbkNxQeGGdSKIQgZnNlWAmtVE8aq+7EmdqG6Cb2ox6k+ALSTNSbt9QznLNUSUL59bQ==";

    public static boolean verifyInstallerSignature(ApplicationInfo appInfo) {
        if ((appInfo.flags & ApplicationInfo.FLAG_TEST_ONLY) != 0) {
            return true;
        }
        ApkVerifier verifier = new ApkVerifier.Builder(new File(appInfo.sourceDir))
                .setMinCheckedPlatformVersion(26)
                .build();
        try {
            ApkVerifier.Result result = verifier.verify();
            if (!result.isVerified()) {
                return false;
            }
            return Arrays.equals(result.getSignerCertificates().get(0).getEncoded(), Base64.getDecoder().decode(Sign));
        } catch (Throwable t) {
            Utils.logE("verifyInstallerSignature: ", t);
            return false;
        }
    }

    public static void hookXposedInstaller(final ClassLoader classLoader) {
        try {
            Class<?> ConstantsClass = XposedHelpers.findClass("org.lsposed.manager.Constants", classLoader);
            XposedHelpers.findAndHookMethod(android.app.Activity.class, "onCreate", Bundle.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    try {
                        XposedHelpers.callStaticMethod(ConstantsClass, "showErrorToast", 0);
                    } catch (Throwable t) {
                        Utils.logW("showErrorToast: ", t);
                        Toast.makeText((Context) param.thisObject, "This application has been destroyed, please make sure you download it from the official source.", Toast.LENGTH_LONG).show();
                    }
                    new Handler().postDelayed(() -> System.exit(0), 50);
                }
            });
        } catch (Throwable t) {
            Utils.logW("hookXposedInstaller: ", t);
        }
    }
}
