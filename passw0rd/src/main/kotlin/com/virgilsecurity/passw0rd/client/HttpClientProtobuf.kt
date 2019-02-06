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

package com.virgilsecurity.passw0rd.client

import com.github.kittinunf.fuel.Fuel
import com.google.protobuf.Message
import com.google.protobuf.Parser
import com.virgilsecurity.passw0rd.data.ProtocolException
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos

/**
 * HttpClientProtobuf class is an implementation of http client specifically for work with Protobuf.
 */
class HttpClientProtobuf(val serviceBaseUrl: String = SERVICE_BASE_URL) {

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
     */
    fun <O> fireGet(
            endpoint: AvailableRequests,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O where O : Message {
        headers.putAll(mapOf(APP_TOKEN_KEY to authToken))
        headers.putAll(mapOf(PROTO_REQUEST_TYPE_KEY to PROTO_REQUEST_TYPE))
        headers.putAll(mapOf(USER_AGENT_KEY to USER_AGENT))

        val response = Fuel.get(serviceBaseUrl + extractRequestType(endpoint))
                .header(headers)
                .response()
                .second

        if (response.statusCode > 299)
            Passw0rdProtos.HttpError.parseFrom(response.data).run {
                throw ProtocolException(this.code, this.message)
            }

        return responseParser.parseFrom(response.data)
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
     */
    fun <O> firePost(
            data: Message,
            endpoint: AvailableRequests,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O where O : Message {
        headers.putAll(mapOf(APP_TOKEN_KEY to authToken))
        headers.putAll(mapOf(PROTO_REQUEST_TYPE_KEY to PROTO_REQUEST_TYPE))
        headers.putAll(mapOf(USER_AGENT_KEY to USER_AGENT))

        val result = Fuel.post(serviceBaseUrl + extractRequestType(endpoint))
                .body(data.toByteArray())
                .header(headers)
                .response()

        val response = result.second

        if (response.statusCode > 299)
            Passw0rdProtos.HttpError.parseFrom(response.data).run {
                throw ProtocolException(this.code, this.message)
            }

        return responseParser.parseFrom(response.data)
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
     */
    fun <I, O> firePut(
            data: I,
            endpoint: AvailableRequests,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O where I : Message, O : Message {
        headers.putAll(mapOf(APP_TOKEN_KEY to authToken))
        headers.putAll(mapOf(PROTO_REQUEST_TYPE_KEY to PROTO_REQUEST_TYPE))
        headers.putAll(mapOf(USER_AGENT_KEY to USER_AGENT))

        val response = Fuel.put(serviceBaseUrl + extractRequestType(endpoint))
                .body(data.toByteArray())
                .header(headers)
                .response()
                .second

        if (response.statusCode > 299)
            Passw0rdProtos.HttpError.parseFrom(response.data).run {
                throw ProtocolException(this.code, this.message)
            }

        return responseParser.parseFrom(response.data)
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
     */
    fun <O> fireDelete(
            endpoint: AvailableRequests,
            headers: MutableMap<String, String> = mutableMapOf(),
            authToken: String,
            responseParser: Parser<O>
    ): O where O : Message {
        headers.putAll(mapOf(APP_TOKEN_KEY to authToken))
        headers.putAll(mapOf(PROTO_REQUEST_TYPE_KEY to PROTO_REQUEST_TYPE))
        headers.putAll(mapOf(USER_AGENT_KEY to USER_AGENT))

        val response = Fuel.delete(serviceBaseUrl + extractRequestType(endpoint))
                .header(headers)
                .response()
                .second

        if (response.statusCode > 299)
            Passw0rdProtos.HttpError.parseFrom(response.data).run {
                throw ProtocolException(this.code, this.message)
            } // TODO try to get message/code if it's not a Passw0rdProtos.HttpError type.

        return responseParser.parseFrom(response.data)
    }

    /**
     * This functions extracts string value from provided [AvailableRequests] parameter.
     */
    private fun extractRequestType(availableRequests: AvailableRequests) =
            when (availableRequests) {
                AvailableRequests.ENROLL -> "/enroll"
                AvailableRequests.VERIFY_PASSWORD -> "/verify-password"
            }

    /**
     * Enum of available requests
     */
    enum class AvailableRequests {
        ENROLL,
        VERIFY_PASSWORD
    }

    companion object {
        private const val SERVICE_VERSION = "v1"
        private const val SERVICE_BASE_URL = "https://api.passw0rd.io/phe/$SERVICE_VERSION"

        private const val PROTO_REQUEST_TYPE_KEY = "Content-Type"
        private const val PROTO_REQUEST_TYPE = "application/protobuf"

        private const val APP_TOKEN_KEY = "AppToken"

        private const val USER_AGENT_KEY = "User-Agent"
        private const val USER_AGENT = "passw0rd/java"
    }
}