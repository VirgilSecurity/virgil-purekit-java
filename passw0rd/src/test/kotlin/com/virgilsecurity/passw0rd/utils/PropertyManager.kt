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

package com.virgilsecurity.passw0rd.utils

object PropertyManager {
    val appToken: String by lazy {
        if (System.getProperty(APP_TOKEN) != null)
            System.getProperty(APP_TOKEN)
        else
            System.getenv(APP_TOKEN)
    }
    val publicKeyOld: String by lazy {
        if (System.getProperty(PUBLIC_KEY_OLD) != null)
            System.getProperty(PUBLIC_KEY_OLD)
        else
            System.getenv(PUBLIC_KEY_OLD)
    }
    val secretKeyOld: String by lazy {
        if (System.getProperty(SECRET_KEY_OLD) != null)
            System.getProperty(SECRET_KEY_OLD)
        else
            System.getenv(SECRET_KEY_OLD)
    }
    val publicKeyNew: String by lazy {
        if (System.getProperty(PUBLIC_KEY_NEW) != null)
            System.getProperty(PUBLIC_KEY_NEW)
        else
            System.getenv(PUBLIC_KEY_NEW)
    }
    val secretKeyNew: String by lazy {
        if (System.getProperty(SECRET_KEY_NEW) != null)
            System.getProperty(SECRET_KEY_NEW)
        else
            System.getenv(SECRET_KEY_NEW)
    }
    val publicKeyWrong: String by lazy {
        if (System.getProperty(PUBLIC_KEY_WRONG) != null)
            System.getProperty(PUBLIC_KEY_WRONG)
        else
            System.getenv(PUBLIC_KEY_WRONG)
    }
    val updateTokenOld: String by lazy {
        if (System.getProperty(UPDATE_TOKEN_OLD) != null)
            System.getProperty(UPDATE_TOKEN_OLD)
        else
            System.getenv(UPDATE_TOKEN_OLD)
    }
    val updateTokenNew: String by lazy {
        if (System.getProperty(UPDATE_TOKEN_NEW) != null)
            System.getProperty(UPDATE_TOKEN_NEW)
        else
            System.getenv(UPDATE_TOKEN_NEW)
    }
    val serverAddress: String by lazy {
        if (System.getProperty(SERVER_ADDRESS) != null)
            System.getProperty(SERVER_ADDRESS)
        else
            System.getenv(SERVER_ADDRESS)
    }

    private const val APP_TOKEN = "APP_TOKEN"
    private const val PUBLIC_KEY_OLD = "PUBLIC_KEY_OLD"
    private const val SECRET_KEY_OLD = "SECRET_KEY_OLD"
    private const val PUBLIC_KEY_NEW = "PUBLIC_KEY_NEW"
    private const val SECRET_KEY_NEW = "SECRET_KEY_NEW"
    private const val PUBLIC_KEY_WRONG = "PUBLIC_KEY_WRONG"
    private const val UPDATE_TOKEN_OLD = "UPDATE_TOKEN_OLD"
    private const val UPDATE_TOKEN_NEW = "UPDATE_TOKEN_NEW"
    private const val SERVER_ADDRESS = "SERVER_ADDRESS"
}