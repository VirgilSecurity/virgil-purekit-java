/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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

package com.virgilsecurity.purekit.utils

import com.virgilsecurity.testcommon.property.EnvPropertyReader
import com.virgilsecurity.testcommon.utils.PropertyUtils

class PropertyManager {

    companion object {
        private const val APP_TOKEN = "APP_TOKEN"
        private const val PHE_PUBLIC_KEY_OLD = "PHE_PUBLIC_KEY_OLD"
        private const val PHE_SECRET_KEY_OLD = "PHE_SECRET_KEY_OLD"
        private const val KMS_PUBLIC_KEY_OLD = "KMS_PUBLIC_KEY_OLD"
        private const val KMS_SECRET_KEY_OLD = "KMS_SECRET_KEY_OLD"
        private const val PHE_PUBLIC_KEY_NEW = "PHE_PUBLIC_KEY_NEW"
        private const val PHE_SECRET_KEY_NEW = "PHE_SECRET_KEY_NEW"
        private const val KMS_PUBLIC_KEY_NEW = "KMS_PUBLIC_KEY_NEW"
        private const val KMS_SECRET_KEY_NEW = "KMS_SECRET_KEY_NEW"
        private const val PHE_PUBLIC_KEY_WRONG = "PHE_PUBLIC_KEY_WRONG"
        private const val PHE_UPDATE_TOKEN = "PHE_UPDATE_TOKEN"
        private const val KMS_UPDATE_TOKEN = "KMS_UPDATE_TOKEN"
        private const val PHE_SERVER_ADDRESS = "PHE_SERVER_ADDRESS"
        private const val PURE_SERVER_ADDRESS = "PURE_SERVER_ADDRESS"
        private const val KMS_SERVER_ADDRESS = "KMS_SERVER_ADDRESS"

        private const val ENVIRONMENT_PARAMETER = "environment"

        @JvmStatic val appToken: String by lazy { envPropertyReader.getProperty(APP_TOKEN) }
        @JvmStatic val phePublicKeyOld: String by lazy { envPropertyReader.getProperty(PHE_PUBLIC_KEY_OLD) }
        @JvmStatic val pheSecretKeyOld: String by lazy { envPropertyReader.getProperty(PHE_SECRET_KEY_OLD) }
        @JvmStatic val kmsPublicKeyOld: String by lazy { envPropertyReader.getProperty(KMS_PUBLIC_KEY_OLD) }
        @JvmStatic val kmsSecretKeyOld: String by lazy { envPropertyReader.getProperty(KMS_SECRET_KEY_OLD) }
        @JvmStatic val phePublicKeyNew: String by lazy { envPropertyReader.getProperty(PHE_PUBLIC_KEY_NEW) }
        @JvmStatic val pheSecretKeyNew: String by lazy { envPropertyReader.getProperty(PHE_SECRET_KEY_NEW) }
        @JvmStatic val kmsPublicKeyNew: String by lazy { envPropertyReader.getProperty(KMS_PUBLIC_KEY_NEW) }
        @JvmStatic val kmsSecretKeyNew: String by lazy { envPropertyReader.getProperty(KMS_SECRET_KEY_NEW) }
        @JvmStatic val phePublicKeyWrong: String by lazy { envPropertyReader.getProperty(PHE_PUBLIC_KEY_WRONG) }
        @JvmStatic val pheUpdateToken: String by lazy { envPropertyReader.getProperty(PHE_UPDATE_TOKEN) }
        @JvmStatic val kmsUpdateToken: String by lazy { envPropertyReader.getProperty(KMS_UPDATE_TOKEN) }
        @JvmStatic val pheServiceAddress: String by lazy { envPropertyReader.getProperty(PHE_SERVER_ADDRESS) }
        @JvmStatic val pureServerAddress: String by lazy { envPropertyReader.getProperty(PURE_SERVER_ADDRESS) }
        @JvmStatic val kmsServerAddress: String by lazy { envPropertyReader.getProperty(KMS_SERVER_ADDRESS) }

        private val envPropertyReader: EnvPropertyReader by lazy {
            val environment = PropertyUtils.getSystemProperty(ENVIRONMENT_PARAMETER)

            if (environment != null)
                EnvPropertyReader.Builder()
                        .environment(EnvPropertyReader.Environment.fromType(environment))
                        .build()
            else
                EnvPropertyReader.Builder()
                        .environment(EnvPropertyReader.Environment.PRO)
                        .build()
        }
    }
}