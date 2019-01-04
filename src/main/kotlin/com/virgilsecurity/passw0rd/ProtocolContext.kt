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

package com.virgilsecurity.passw0rd

import com.google.protobuf.ByteString
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos
import com.virgilsecurity.passw0rd.utils.Utils
import virgil.crypto.phe.PheClient
import java.lang.IllegalArgumentException
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
    val updateToken: Passw0rdProtos.VersionedUpdateToken
) {

    companion object {
        fun create(
            appToken: String,
            servicePublicKey: String,
            clientSecretKey: String,
            updateToken: String
        ): ProtocolContext {
            if (appToken.isBlank()) Utils.shouldNotBeEmpty("appToken")
            if (servicePublicKey.isBlank()) Utils.shouldNotBeEmpty("clientSecretKey")
            if (clientSecretKey.isBlank()) Utils.shouldNotBeEmpty("servicePublicKey")

            val (version, content) = parseToken(updateToken)

            val versionedUpdateToken = Passw0rdProtos.VersionedUpdateToken
                .newBuilder()
                .setVersion(version)
                .setUpdateToken(ByteString.copyFrom(content))
                .build()

            return ProtocolContext(appToken, PheClient(), version, versionedUpdateToken)
        }

        private fun parseToken(token: String): Pair<Int, ByteArray> {
            if (token.isBlank()) Utils.shouldNotBeEmpty("token")

            val tokenParts = token.split('.')
            if (tokenParts.size != 3)
                throw IllegalArgumentException(
                    "Provided \'token\' has wrong parts count. " +
                            "Should be \'3\'. Actual is \'{${tokenParts.size}}\'. "
                )

            if (tokenParts[0] != UPDATE_TOKEN_PREFIX)
                throw IllegalArgumentException(
                    "Wrong token prefix. Should be \'$UPDATE_TOKEN_PREFIX\'. " +
                            "Actual is \'{$tokenParts[0]}\'."
                )

            val version: Int
            try {
                version = tokenParts[1].toInt()
                if (version < 1)
                    throw IllegalArgumentException("Token version can not be zero or negative number.")
            } catch (e: NumberFormatException) {
                throw IllegalArgumentException("Token version can not be parsed.")
            }

            val content: ByteArray
            try {
                content = Base64.getDecoder().decode(tokenParts[2])
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Token content can not be parsed.")
            }

            return Pair(version, content)
        }

        const val UPDATE_TOKEN_PREFIX = "UT"
    }
}