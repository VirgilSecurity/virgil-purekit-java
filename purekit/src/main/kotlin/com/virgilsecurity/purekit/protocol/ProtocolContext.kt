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

package com.virgilsecurity.purekit.protocol

import com.google.protobuf.ByteString
import com.virgilsecurity.crypto.phe.PheClient
import com.virgilsecurity.purekit.data.NoKeysFoundException
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos
import com.virgilsecurity.purekit.utils.*

/**
 * ProtocolContext class holds and validates protocol input parameters.
 */
class ProtocolContext private constructor(
        val appToken: String,
        val pheClients: Map<Int, PheClient>,
        val version: Int,
        val updateToken: PurekitProtos.VersionedUpdateToken?
) {

    companion object {
        /**
         * This function validates input parameters and prepares them for being used in Protocol.
         */
        @JvmStatic
        fun create(
                appToken: String,
                servicePublicKey: String,
                clientSecretKey: String,
                updateToken: String
        ): ProtocolContext {
            requires(appToken.isNotBlank(), "appToken")
            requires(servicePublicKey.isNotBlank(), "servicePublicKey")
            requires(clientSecretKey.isNotBlank(), "clientSecretKey")

            val (publicVersion, publicBytes) = servicePublicKey.parseVersionAndContent(
                    PREFIX_PUBLIC_KEY,
                    KEY_PUBLIC_KEY
            )

            val (secretVersion, secretBytes) = clientSecretKey.parseVersionAndContent(
                    PREFIX_SECRET_KEY,
                    KEY_SECRET_KEY
            )

            require(publicVersion == secretVersion) { "Public and Secret keys must have the same version." }

            val pheClients = mutableMapOf<Int, PheClient>().apply {
                put(publicVersion,
                    PheClient().apply {
                        setupDefaults()
                        setKeys(secretBytes, publicBytes)
                    })
            }

            var currentVersion = publicVersion
            var versionedUpdateToken: PurekitProtos.VersionedUpdateToken? = null

            if (updateToken.isNotBlank()) {
                val (tokenVersion, content) = updateToken.parseVersionAndContent(
                        PREFIX_UPDATE_TOKEN,
                        KEY_UPDATE_TOKEN
                )

                require(tokenVersion == currentVersion + 1) {
                    "Incorrect token version $tokenVersion. Should be {$tokenVersion + 1}."
                }

                currentVersion = tokenVersion

                val pheClient = pheClients[publicVersion]
                        ?: throw NoKeysFoundException("Unable to find keys corresponding to " +
                                                              "record's version $publicVersion.")

                val rotateKeysResult = pheClient.rotateKeys(content)

                pheClients[tokenVersion] = PheClient().apply {
                    setupDefaults()
                    setKeys(rotateKeysResult.newClientPrivateKey, rotateKeysResult.newServerPublicKey)
                }

                versionedUpdateToken = PurekitProtos.VersionedUpdateToken
                        .newBuilder()
                        .setVersion(tokenVersion)
                        .setUpdateToken(ByteString.copyFrom(content))
                        .build()
            }

            return ProtocolContext(appToken, pheClients, currentVersion, versionedUpdateToken)
        }
    }
}