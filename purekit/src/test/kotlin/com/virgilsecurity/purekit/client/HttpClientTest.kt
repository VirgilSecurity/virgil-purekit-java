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

package com.virgilsecurity.purekit.client

import com.virgilsecurity.purekit.data.ProtocolException
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos
import com.virgilsecurity.purekit.utils.PREFIX_PURE_APP_TOKEN
import com.virgilsecurity.purekit.utils.PREFIX_VIRGIL_APP_TOKEN
import com.virgilsecurity.purekit.utils.PropertyManager
import com.virgilsecurity.purekit.utils.prefix
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.*

/**
 * HttpClientTest class.
 */
class HttpClientTest {

    @ParameterizedTest @MethodSource("testArguments")
    fun response_proto_parse(serverAddress: String?, appToken: String, publicKeyNew: String) {
        val httpClient = if (serverAddress != null) {
            HttpClientProtobuf(serverAddress)
        } else {
            when {
                appToken.prefix() == PREFIX_PURE_APP_TOKEN ->
                    HttpClientProtobuf(HttpClientProtobuf.DefaultBaseUrls.PASSW0RD.url)
                appToken.prefix() == PREFIX_VIRGIL_APP_TOKEN ->
                    HttpClientProtobuf(HttpClientProtobuf.DefaultBaseUrls.VIRGIL.url)
                else -> throw IllegalArgumentException("Wrong App token prefix")
            }
        }

        val version = parseVersionAndContent(
                publicKeyNew,
                PREFIX_PUBLIC_KEY,
                KEY_PUBLIC_KEY
        ).first

        try {
            PurekitProtos.EnrollmentRequest.newBuilder().setVersion(version).build().run {
                httpClient.firePost(
                        this,
                        HttpClientProtobuf.AvailableRequests.ENROLL.type,
                        authToken = WRONG_TOKEN,
                        responseParser = PurekitProtos.EnrollmentResponse.parser()
                )
            }
        } catch (t: Throwable) {
            assertTrue(t is ProtocolException)
        }
    }

    /**
     * This function is taken from [ProtocolContext]
     */
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

    companion object {
        private const val PREFIX_PUBLIC_KEY = "PK"
        private const val KEY_PUBLIC_KEY = "Public Key"

        private const val WRONG_TOKEN = "WRONG_TOKEN"

        @JvmStatic fun testArguments() = listOf(
                Arguments.of(PropertyManager.virgilPheServerAddress,
                             PropertyManager.virgilAppToken,
                             PropertyManager.virgilPublicKeyNew)
        )
    }
}
