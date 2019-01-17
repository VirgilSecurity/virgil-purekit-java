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

package com.virgilsecurity.passw0rd

import com.google.protobuf.ByteString
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos
import com.virgilsecurity.passw0rd.utils.Utils
import virgil.crypto.phe.PheClient
import java.util.*

/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    12/13/18
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

/**
 * ProtocolContext class.
 */
class ProtocolContext(
    val appToken: String,
    val pheClient: PheClient,
    val version: Int,
    val updateToken: Passw0rdProtos.VersionedUpdateToken?
) {

    companion object {
        fun create(
            appToken: String,
            servicePublicKey: String,
            clientSecretKey: String,
            updateToken: String
        ): ProtocolContext {
            if (appToken.isBlank()) Utils.shouldNotBeEmpty("appToken")
            if (servicePublicKey.isBlank()) Utils.shouldNotBeEmpty("servicePublicKey")
            if (clientSecretKey.isBlank()) Utils.shouldNotBeEmpty("clientSecretKey")

            val (publicVersion, publicBytes) = parseVersionAndContent(
                servicePublicKey,
                PREFIX_PUBLIC_KEY,
                KEY_PUBLIC_KEY
            )

            val (secretVersion, secretBytes) = parseVersionAndContent(
                clientSecretKey,
                PREFIX_SECRET_KEY,
                KEY_SECRET_KEY
            )

            if (publicVersion != secretVersion)
                throw IllegalArgumentException("Public and Secret keys must have the same version.")

            var pheClient = PheClient()
            pheClient.setKeys(secretBytes, publicBytes)

            var currentVersion = publicVersion
            var versionedUpdateToken: Passw0rdProtos.VersionedUpdateToken? = null

            if (updateToken.isNotBlank()) {
                val (tokenVersion, content) = parseVersionAndContent(
                    updateToken,
                    PREFIX_UPDATE_TOKEN,
                    KEY_UPDATE_TOKEN
                )

                if (tokenVersion != currentVersion + 1)
                    throw IllegalArgumentException(
                        "Incorrect token version $tokenVersion. " +
                                "Should be {$tokenVersion + 1}."
                    )

                currentVersion = tokenVersion

                val rotateKeysResult = pheClient.rotateKeys(content)

                pheClient = PheClient() // New client for new keys
                pheClient.setKeys(rotateKeysResult.newClientPrivateKey, rotateKeysResult.newServerPublicKey)

                versionedUpdateToken = Passw0rdProtos.VersionedUpdateToken
                    .newBuilder()
                    .setVersion(tokenVersion)
                    .setUpdateToken(ByteString.copyFrom(content))
                    .build()
            }

            return ProtocolContext(appToken, pheClient, currentVersion, versionedUpdateToken)
        }

        private fun parseVersionAndContent(forParse: String, prefix: String, name: String): Pair<Int, ByteArray> {
            val parsedParts = forParse.split('.')
            if (parsedParts.size != 3)
                throw java.lang.IllegalArgumentException(
                    "Provided \'$name\' has wrong parts count. " +
                            "Should be \'3\'. Actual is \'{${parsedParts.size}}\'. "
                )

            if (parsedParts[0] != prefix)
                throw java.lang.IllegalArgumentException(
                    "Wrong token prefix. Should be \'$prefix\'. " +
                            "Actual is \'{$parsedParts[0]}\'."
                )

            val version: Int
            try {
                version = parsedParts[1].toInt()
                if (version < 1)
                    throw java.lang.IllegalArgumentException("$name version can not be zero or negative number.")
            } catch (e: NumberFormatException) {
                throw java.lang.IllegalArgumentException("$name version can not be parsed.")
            }

            val content: ByteArray
            try {
                content = Base64.getDecoder().decode(parsedParts[2])
            } catch (e: java.lang.IllegalArgumentException) {
                throw java.lang.IllegalArgumentException("$name content can not be parsed.")
            }

            return Pair(version, content)
        }

        private const val PREFIX_UPDATE_TOKEN = "UT"
        private const val PREFIX_SECRET_KEY = "SK"
        private const val PREFIX_PUBLIC_KEY = "PK"

        private const val KEY_UPDATE_TOKEN = "Update Token"
        private const val KEY_SECRET_KEY = "Secret Key"
        private const val KEY_PUBLIC_KEY = "Public Key"
    }
}