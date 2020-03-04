/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.purekit;

import com.virgilsecurity.testcommon.property.EnvPropertyReader;
import com.virgilsecurity.testcommon.utils.PropertyUtils;

public class PropertyManager {
    private static String APP_TOKEN = "APP_TOKEN";
    private static String PUBLIC_KEY_OLD = "PUBLIC_KEY_OLD";
    private static String SECRET_KEY_OLD = "SECRET_KEY_OLD";
    private static String PUBLIC_KEY_NEW = "PUBLIC_KEY_NEW";
    private static String SECRET_KEY_NEW = "SECRET_KEY_NEW";
    private static String UPDATE_TOKEN = "UPDATE_TOKEN";
    private static String PHE_SERVER_ADDRESS = "PHE_SERVER_ADDRESS";
    private static String PURE_SERVER_ADDRESS = "PURE_SERVER_ADDRESS";
    private static String KMS_SERVER_ADDRESS = "KMS_SERVER_ADDRESS";
    private static String ENVIRONMENT_PARAMETER = "environment";

    private EnvPropertyReader envPropertyReader;
    private String env;

    PropertyManager() {
        String environment = PropertyUtils.getSystemProperty(ENVIRONMENT_PARAMETER);
        this.env = environment;

        if (environment != null) {
            envPropertyReader = new EnvPropertyReader.Builder()
                    .environment(EnvPropertyReader.Environment.fromType(environment))
                    .build();
        } else {
            this.env = EnvPropertyReader.Environment.PRO.toString();
            envPropertyReader = new EnvPropertyReader.Builder()
                    .environment(EnvPropertyReader.Environment.PRO)
                    .build();
        }
    }

    public String getPheServiceAddress() {
        return envPropertyReader.getProperty(PHE_SERVER_ADDRESS);
    }

    public String getPureServerAddress() {
        return envPropertyReader.getProperty(PURE_SERVER_ADDRESS);
    }

    public String getKmsServerAddress() {
        return envPropertyReader.getProperty(KMS_SERVER_ADDRESS);
    }

    public String getAppToken() {
        return envPropertyReader.getProperty(APP_TOKEN);
    }

    public String getPublicKeyOld() {
        return envPropertyReader.getProperty(PUBLIC_KEY_OLD);
    }

    public String getSecretKeyOld() {
        return envPropertyReader.getProperty(SECRET_KEY_OLD);
    }

    public String getUpdateToken() {
        return envPropertyReader.getProperty(UPDATE_TOKEN);
    }

    public String getPublicKeyNew() {
        return envPropertyReader.getProperty(PUBLIC_KEY_NEW);
    }

    public String getSecretKeyNew() {
        return envPropertyReader.getProperty(SECRET_KEY_NEW);
    }

    public String getEnv() {
        return env;
    }
}
