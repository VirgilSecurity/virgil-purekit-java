import client.PheClient
import crypto.PheCrypto
import stubs.PublicKey
import stubs.SecretKey
import stubs.UpdateToken
import java.util.*

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
class ProtocolContext {

    private val clientSecretKeys: Map<Int, SecretKey>
    private val serverPublicKeys: Map<Int, PublicKey>

    val appId: String
    val pheClient: PheClient
    val pheCrypto: PheCrypto

    val updateTokens: Collection<UpdateToken>

    var actualVersion: Int = 0
        get() = clientSecretKeys.size - 1

    fun getActualClientSecretKey() = clientSecretKeys[actualVersion]

    fun getActualServerPublicKey() = serverPublicKeys[actualVersion]

    fun getClientSecretKeyForVersion(version: Int) = clientSecretKeys[version]

    fun getServerPublicKeyForVersion(version: Int) = serverPublicKeys[version]

    companion object {
        fun create(
            appId: String,
            accessToken: String,
            serverPublicKey: String,
            clientSecretKey: String,
            updateTokens: Collection<String>? = null
        ): ProtocolContext {

        }

        fun ensureServerPublicKey(serverPublicKey: String, pheCrypto: PheCrypto): Pair<Int, PublicKey> {

        }

        fun ensureClientSecretKey(clientSecretKey: String, pheCrypto: PheCrypto): Pair<Int, SecretKey> {

        }
    }
}