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

package com.virgilsecurity.purekit.protocol

import com.virgilsecurity.purekit.utils.PropertyManager
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

/**
 * ProtocolContextTest class.
 */
class ProtocolContextTest {

    // HTC-8
    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    fun one_key_context(appToken: String, publicKeyNew: String, secretKeyNew: String) {
        val context = ProtocolContext.create(appToken, publicKeyNew, secretKeyNew, "")
        assertNotNull(context)
        assertEquals(2, context.version)
        assertEquals(1, context.pheClients.size)
        assertNull(context.updateToken)
    }

    // HTC-9
    @ParameterizedTest @MethodSource("testArguments")
    fun context_with_update_token(appToken: String, publicKeyOld: String, secretKeyOld: String, updateTokenOld: String) {
        val context = ProtocolContext.create(appToken, publicKeyOld, secretKeyOld, updateTokenOld)
        assertNotNull(context)
        assertEquals(2, context.version)
        assertNotNull(context.updateToken)
        assertNotNull(context.pheClients[context.updateToken!!.version]) // Current keys
        assertNotNull(context.pheClients[context.updateToken!!.version - 1]) // Previous keys
    }

    // HTC-10
    @Test fun context_with_wrong_update_token() {
        assertThrows<IllegalArgumentException> {
            ProtocolContext.create(PropertyManager.virgilAppToken,
                                   PropertyManager.virgilPublicKeyOld,
                                   PropertyManager.virgilSecretKeyOld,
                                   PropertyManager.virgilUpdateTokenNew
            )
        }
    }

    companion object {

        @JvmStatic fun testArgumentsNoToken() = listOf(
                Arguments.of(PropertyManager.virgilAppToken,
                             PropertyManager.virgilPublicKeyNew,
                             PropertyManager.virgilSecretKeyNew),
                Arguments.of(PropertyManager.purekitAppToken,
                             PropertyManager.purekitPublicKeyNew,
                             PropertyManager.purekitSecretKeyNew)
        )

        @JvmStatic fun testArguments() = listOf(
                Arguments.of(PropertyManager.virgilAppToken,
                             PropertyManager.virgilPublicKeyOld,
                             PropertyManager.virgilSecretKeyOld,
                             PropertyManager.virgilUpdateTokenOld),
                Arguments.of(PropertyManager.purekitAppToken,
                             PropertyManager.purekitPublicKeyOld,
                             PropertyManager.purekitSecretKeyOld,
                             PropertyManager.purekitUpdateTokenOld)
        )
    }
}