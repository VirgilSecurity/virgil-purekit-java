/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

package com.virgilsecurity.passw0rd.protocol

import com.google.protobuf.ByteString
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos
import com.virgilsecurity.passw0rd.utils.Utils
import virgil.crypto.phe.PheClient

/**
 * Created by: Danylo Oliinyk.
 * On 12/13/2018 at Virgil Security.
 */

/**
 * ProtocolContext class holds and validates protocol input parameters.
 */
class ProtocolContext private constructor(
        val appToken: String,
        val pheClients: Map<Int, PheClient>,
        val version: Int,
        val updateToken: Passw0rdProtos.VersionedUpdateToken?
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
            if (appToken.isBlank()) Utils.shouldNotBeEmpty("appToken")
            if (servicePublicKey.isBlank()) Utils.shouldNotBeEmpty("servicePublicKey")
            if (clientSecretKey.isBlank()) Utils.shouldNotBeEmpty("clientSecretKey")

            val (publicVersion, publicBytes) = Utils.parseVersionAndContent(
                    servicePublicKey,
                    Utils.PREFIX_PUBLIC_KEY,
                    Utils.KEY_PUBLIC_KEY
            )

            val (secretVersion, secretBytes) = Utils.parseVersionAndContent(
                    clientSecretKey,
                    Utils.PREFIX_SECRET_KEY,
                    Utils.KEY_SECRET_KEY
            )

            if (publicVersion != secretVersion)
                throw IllegalArgumentException("Public and Secret keys must have the same version.")

            val pheClients = mutableMapOf<Int, PheClient>().apply {
                put(publicVersion, PheClient().apply { setKeys(secretBytes, publicBytes) })
            }

            var currentVersion = publicVersion
            var versionedUpdateToken: Passw0rdProtos.VersionedUpdateToken? = null

            if (updateToken.isNotBlank()) {
                val (tokenVersion, content) = Utils.parseVersionAndContent(
                        updateToken,
                        Utils.PREFIX_UPDATE_TOKEN,
                        Utils.KEY_UPDATE_TOKEN
                )

                if (tokenVersion != currentVersion + 1)
                    throw IllegalArgumentException("Incorrect token version $tokenVersion. " +
                                                           "Should be {$tokenVersion + 1}.")

                currentVersion = tokenVersion

                val rotateKeysResult = pheClients[publicVersion]!!.rotateKeys(content)

                pheClients[tokenVersion] = PheClient().apply {
                    setKeys(rotateKeysResult.newClientPrivateKey, rotateKeysResult.newServerPublicKey)
                }

                versionedUpdateToken = Passw0rdProtos.VersionedUpdateToken
                        .newBuilder()
                        .setVersion(tokenVersion)
                        .setUpdateToken(ByteString.copyFrom(content))
                        .build()
            }

            return ProtocolContext(appToken,
                                                                        pheClients,
                                                                        currentVersion,
                                                                        versionedUpdateToken)
        }
    }
}