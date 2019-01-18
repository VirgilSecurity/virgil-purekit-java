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
        val secretKey: String by lazy {
            if (System.getProperty(SECRET_KEY) != null)
                System.getProperty(SECRET_KEY)
            else
                System.getenv(SECRET_KEY)
        }
        val publicKey: String by lazy {
            if (System.getProperty(PUBLIC_KEY) != null)
                System.getProperty(PUBLIC_KEY)
            else
                System.getenv(PUBLIC_KEY)
        }
        val updateToken: String by lazy {
            if (System.getProperty(UPDATE_TOKEN) != null)
                System.getProperty(UPDATE_TOKEN)
            else
                System.getenv(UPDATE_TOKEN)
        }
        val serverAddress: String by lazy {
            if (System.getProperty(SERVER_ADDRESS) != null)
                System.getProperty(SERVER_ADDRESS)
            else
                System.getenv(SERVER_ADDRESS)
        }

        private const val APP_TOKEN = "APP_TOKEN"
        private const val SECRET_KEY = "SECRET_KEY"
        private const val PUBLIC_KEY = "PUBLIC_KEY"
        private const val UPDATE_TOKEN = "UPDATE_TOKEN"
        private const val SERVER_ADDRESS = "SERVER_ADDRESS"
    }