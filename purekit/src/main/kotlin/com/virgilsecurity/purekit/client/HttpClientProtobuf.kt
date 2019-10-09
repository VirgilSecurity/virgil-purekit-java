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

import com.github.kittinunf.fuel.core.Response
import com.github.kittinunf.fuel.core.isSuccessful
import com.github.kittinunf.fuel.httpDelete
import com.github.kittinunf.fuel.httpGet
import com.github.kittinunf.fuel.httpPost
import com.github.kittinunf.fuel.httpPut
import com.google.protobuf.InvalidProtocolBufferException
import com.google.protobuf.Message
import com.google.protobuf.Parser
import com.virgilsecurity.purekit.build.VersionVirgilAgent
import com.virgilsecurity.purekit.data.ProtocolException
import com.virgilsecurity.purekit.data.ProtocolHttpException
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos
import com.virgilsecurity.purekit.utils.OsUtils

/**
 * HttpClientProtobuf class is an implementation of http client specifically for work with Protobuf.
 */
class HttpClientProtobuf {

    private val virgilAgentHeader: String
    private val serviceBaseUrl: String

    constructor(serviceBaseUrl: String = VIRGIL_SERVICE_BASE_URL) {
        virgilAgentHeader =
                "$VIRGIL_AGENT_PRODUCT;$VIRGIL_AGENT_FAMILY;${OsUtils.osAgentName};${VersionVirgilAgent.VERSION}"
        this.serviceBaseUrl = serviceBaseUrl
    }

    constructor(product: String, version: String, serviceBaseUrl: String = VIRGIL_SERVICE_BASE_URL) {
        virgilAgentHeader = "$product;$VIRGIL_AGENT_FAMILY;${OsUtils.osAgentName};$version"
        this.serviceBaseUrl = serviceBaseUrl
    }

    /**
     * This function issues GET request to the specified [serviceBaseUrl] (or default one if not specified) + provided
     * [endpoint] (Request address will be: [serviceBaseUrl]/[endpoint]).
     *
     * You can provide your headers, but keep in mind that *AppToken*, *User-Agent* and *Content-Type* are already
     * present (and will be overridden if you try to provide them).
     *
     * For authorization provided [authToken] will be mapped to *AppToken* key in header.
     *
     * You have to specify [responseParser] that will be used to parse Protobuf message that service will answer to
     * your request. It should be correct Protobuf message. To get [Parser] you have to call *<YourProto>.parser()*
     * function. The type of [Parser] you specified is your *return* type.
     *
     * @throws ProtocolException
     * @throws ProtocolHttpException
     */
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun <O : Message> fireGet(
            endpoint: String,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O? {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpGet()
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
        return responseParser.parseFrom(response.data)
    }

    /**
     * This function issues GET request to the specified [serviceBaseUrl] (or default one if not specified) + provided
     * [endpoint] (Request address will be: [serviceBaseUrl]/[endpoint]).
     *
     * You can provide your headers, but keep in mind that *AppToken*, *User-Agent* and *Content-Type* are already
     * present (and will be overridden if you try to provide them).
     *
     * For authorization provided [authToken] will be mapped to *AppToken* key in header.
     *
     * @throws ProtocolException
     * @throws ProtocolHttpException
     */
    // FIXME What should be fixed? it's just another method - without return type and last parameter
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun fireGet(endpoint: String, headers: MutableMap<String, String> = mutableMapOf(), authToken: String) {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpGet()
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
    }

    /**
     * This function issues POST request to the specified [serviceBaseUrl] (or default one if not specified) + provided
     * [endpoint] (Request address will be: [serviceBaseUrl]/[endpoint]).
     *
     * Provided [data] will be serialized to [ByteArray] and placed in the *body* of this request and should be correct
     * Protobuf message.
     *
     * You can provide your headers, but keep in mind that *AppToken*, *User-Agent* and *Content-Type* are already
     * present (and will be overridden if you try to provide them).
     *
     * For authorization provided [authToken] will be mapped to *AppToken* key in header.
     *
     * You have to specify [responseParser] that will be used to parse Protobuf message that service will answer to
     * your request. It should be correct Protobuf message. To get [Parser] you have to call *<YourProto>.parser()*
     * function. The type of [Parser] you specified is your *return* type.
     *
     * @throws ProtocolException
     * @throws ProtocolHttpException
     */
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun <O : Message> firePost(
            data: Message,
            endpoint: String,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpPost()
                .body(data.toByteArray())
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
        return responseParser.parseFrom(response.data)
    }

    // FIXME What should be fixed? it's just another method - without return type and last parameter
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun firePost(
            data: Message,
            endpoint: String,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String
    ) {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpPost()
                .body(data.toByteArray())
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
    }

    /**
     * This function issues PUT request to the specified [serviceBaseUrl] (or default one if not specified) + provided
     * [endpoint] (Request address will be: [serviceBaseUrl]/[endpoint]).
     *
     * Provided [data] will be serialized to [ByteArray] and placed in the *body* of this request and should be correct
     * Protobuf message.
     *
     * You can provide your headers, but keep in mind that *AppToken*, *User-Agent* and *Content-Type* are already
     * present (and will be overridden if you try to provide them).
     *
     * For authorization provided [authToken] will be mapped to *AppToken* key in header.
     *
     * You have to specify [responseParser] that will be used to parse Protobuf message that service will answer to
     * your request. It should be correct Protobuf message. To get [Parser] you have to call *<YourProto>.parser()*
     * function. The type of [Parser] you specified is your *return* type.
     *
     * @throws ProtocolException
     * @throws ProtocolHttpException
     */
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun <O : Message> firePut(
            data: Message,
            endpoint: String,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpPut()
                .body(data.toByteArray())
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
        return responseParser.parseFrom(response.data)
    }

    // FIXME What should be fixed? it's just another method - without return type and last parameter
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun firePut(
            data: Message,
            endpoint: String,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String
    ) {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpPut()
                .body(data.toByteArray())
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
    }

    /**
     * This function issues DELETE request to the specified [serviceBaseUrl] (or default one if not specified)
     * + provided [endpoint] (Request address will be: [serviceBaseUrl]/[endpoint]).
     *
     * You can provide your headers, but keep in mind that *AppToken*, *User-Agent* and *Content-Type* are already
     * present (and will be overridden if you try to provide them).
     *
     * For authorization provided [authToken] will be mapped to *AppToken* key in header.
     *
     * You have to specify [responseParser] that will be used to parse Protobuf message that service will answer to
     * your request. It should be correct Protobuf message. To get [Parser] you have to call *<YourProto>.parser()*
     * function. The type of [Parser] you specified is your *return* type.
     *
     * @throws ProtocolException
     * @throws ProtocolHttpException
     */
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun <O : Message> fireDelete(
            endpoint: String,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpDelete()
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
        return responseParser.parseFrom(response.data)
    }

    // FIXME What should be fixed? it's just another method - without return type and last parameter
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    fun fireDelete(
            endpoint: String,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String
    ) {
        headers.addConstHeaders().addTokenHeader(authToken)

        val (_, response, _) = "$serviceBaseUrl${endpoint}".httpDelete()
                .header(headers)
                .response()

        checkIfResponseSuccessful(response)
    }

    /**
     * Throws an [ProtocolException] or [ProtocolHttpException] if the [response] is not successful.
     */
    @Throws(ProtocolException::class, ProtocolHttpException::class)
    private fun checkIfResponseSuccessful(response: Response) {
        if (!response.isSuccessful) {
            try {
                val error = PurekitProtos.HttpError.parseFrom(response.data)
                throw ProtocolException(error.code, error.message)
            } catch (exception: InvalidProtocolBufferException) {
                val errorMessage = String(response.data)
                if (errorMessage.isNotBlank())
                    throw ProtocolHttpException(message = errorMessage)
                else
                    throw ProtocolHttpException(response.statusCode, response.responseMessage)
            }
        }
    }

    private fun MutableMap<String, String>.addConstHeaders(): MutableMap<String, String> =
            this.putAll(
                    mapOf(
                            PROTO_REQUEST_TYPE_KEY to PROTO_REQUEST_TYPE,
                            USER_AGENT_KEY to USER_AGENT,
                            VIRGIL_AGENT_HEADER_KEY to virgilAgentHeader
                    )
            ).let { this }

    private fun MutableMap<String, String>.addTokenHeader(authToken: String): MutableMap<String, String> =
            this.put(APP_TOKEN_KEY, authToken).let { this }

    // FIXME: This should be moved to HttpPureClient
    companion object {
        private const val SERVICE_VERSION = "v1"
        private const val PURE_SERVICE_BASE_URL = "https://api.passw0rd.io/phe/$SERVICE_VERSION"
        private const val VIRGIL_SERVICE_BASE_URL = "https://api.virgilsecurity.com/phe/$SERVICE_VERSION"

        private const val PROTO_REQUEST_TYPE_KEY = "Content-Type"
        private const val PROTO_REQUEST_TYPE = "application/protobuf"

        private const val APP_TOKEN_KEY = "AppToken"

        private const val USER_AGENT_KEY = "User-Agent"
        private const val USER_AGENT = "purekit/java"

        private const val VIRGIL_AGENT_HEADER_KEY = "virgil-agent"
        private const val VIRGIL_AGENT_PRODUCT = "purekit"
        private const val VIRGIL_AGENT_FAMILY = "jvm"
    }

    /**
     * Enum of available requests
     */
    // FIXME: Move this out -> Why do you want to move it out? HttpClientProtobuf.AvailableRequests looks good. It says
    // that AvailableRequests are belong to HttpClientProtobuf.
    enum class AvailableRequests(val type: String) {
        ENROLL("/enroll"),
        VERIFY_PASSWORD("/verify-password"),

        INSERT_USER("/user"),
        UPDATE_USER("/user/%s"),
        GET_USER("/user/%s"),
        GET_USERS("/get-users"),
        DELETE_USER("/user/%s?cascade=%s"),
        INSERT_CELL_KEY("/cell-key"),
        UPDATE_CELL_KEY("/cell-key/%s/%s"),
        GET_CELL_KEY("/cell-key/%s/%s"),
        DELETE_CELL_KEY("/cell-key/%s/%s")
    }

    enum class DefaultBaseUrls(val url: String) {
        PASSW0RD(PURE_SERVICE_BASE_URL),
        VIRGIL(VIRGIL_SERVICE_BASE_URL)
    }
}
