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

object PropertyManager {

    // Virgil parameters

    @JvmStatic
    val virgilAppToken: String by lazy {
        if (System.getProperty(VIRGIL_APP_TOKEN) != null)
            System.getProperty(VIRGIL_APP_TOKEN)
        else
            System.getenv(VIRGIL_APP_TOKEN)
    }
    @JvmStatic
    val virgilPublicKeyOld: String by lazy {
        if (System.getProperty(VIRGIL_PUBLIC_KEY_OLD) != null)
            System.getProperty(VIRGIL_PUBLIC_KEY_OLD)
        else
            System.getenv(VIRGIL_PUBLIC_KEY_OLD)
    }
    @JvmStatic
    val virgilSecretKeyOld: String by lazy {
        if (System.getProperty(VIRGIL_SECRET_KEY_OLD) != null)
            System.getProperty(VIRGIL_SECRET_KEY_OLD)
        else
            System.getenv(VIRGIL_SECRET_KEY_OLD)
    }
    @JvmStatic
    val virgilPublicKeyNew: String by lazy {
        if (System.getProperty(VIRGIL_PUBLIC_KEY_NEW) != null)
            System.getProperty(VIRGIL_PUBLIC_KEY_NEW)
        else
            System.getenv(VIRGIL_PUBLIC_KEY_NEW)
    }
    @JvmStatic
    val virgilSecretKeyNew: String by lazy {
        if (System.getProperty(VIRGIL_SECRET_KEY_NEW) != null)
            System.getProperty(VIRGIL_SECRET_KEY_NEW)
        else
            System.getenv(VIRGIL_SECRET_KEY_NEW)
    }
    @JvmStatic
    val virgilPublicKeyWrong: String by lazy {
        if (System.getProperty(VIRGIL_PUBLIC_KEY_WRONG) != null)
            System.getProperty(VIRGIL_PUBLIC_KEY_WRONG)
        else
            System.getenv(VIRGIL_PUBLIC_KEY_WRONG)
    }
    @JvmStatic
    val virgilUpdateTokenOld: String by lazy {
        if (System.getProperty(VIRGIL_UPDATE_TOKEN_OLD) != null)
            System.getProperty(VIRGIL_UPDATE_TOKEN_OLD)
        else
            System.getenv(VIRGIL_UPDATE_TOKEN_OLD)
    }
    @JvmStatic
    val virgilUpdateTokenNew: String by lazy {
        if (System.getProperty(VIRGIL_UPDATE_TOKEN_NEW) != null)
            System.getProperty(VIRGIL_UPDATE_TOKEN_NEW)
        else
            System.getenv(VIRGIL_UPDATE_TOKEN_NEW)
    }
    @JvmStatic
    val serviceAddress: String? by lazy {
        if (System.getProperty(VIRGIL_PHE_SERVER_ADDRESS) != null)
            System.getProperty(VIRGIL_PHE_SERVER_ADDRESS)
        else
            System.getenv(VIRGIL_PHE_SERVER_ADDRESS)
    }

    private const val VIRGIL_APP_TOKEN = "VIRGIL_APP_TOKEN"
    private const val VIRGIL_PUBLIC_KEY_OLD = "VIRGIL_PUBLIC_KEY_OLD"
    private const val VIRGIL_SECRET_KEY_OLD = "VIRGIL_SECRET_KEY_OLD"
    private const val VIRGIL_PUBLIC_KEY_NEW = "VIRGIL_PUBLIC_KEY_NEW"
    private const val VIRGIL_SECRET_KEY_NEW = "VIRGIL_SECRET_KEY_NEW"
    private const val VIRGIL_PUBLIC_KEY_WRONG = "VIRGIL_PUBLIC_KEY_WRONG"
    private const val VIRGIL_UPDATE_TOKEN_OLD = "VIRGIL_UPDATE_TOKEN_OLD"
    private const val VIRGIL_UPDATE_TOKEN_NEW = "VIRGIL_UPDATE_TOKEN_NEW"
    private const val VIRGIL_PHE_SERVER_ADDRESS = "VIRGIL_PHE_SERVER_ADDRESS"
}