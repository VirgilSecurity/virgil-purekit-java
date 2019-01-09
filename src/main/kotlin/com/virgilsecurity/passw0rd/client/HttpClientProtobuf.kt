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
import com.google.protobuf.*
import com.virgilsecurity.passw0rd.data.ProtocolException
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos

/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    2019-01-03
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

/**
 * HttpClientProtobuf class.
 */
class HttpClientProtobuf(val serviceBaseUrl: String = SERVICE_BASE_URL) { // TODO catch service errors

    fun fireGet(
        endpoint: AvailableRequests,
        headers: MutableMap<String, String> = mutableMapOf(),
        authToken: String,
        responseType: Message
    ): Message {
        headers.putAll(mapOf(APP_TOKEN_KEY to authToken))
        headers.putAll(mapOf(PROTO_REQUEST_TYPE_KEY to PROTO_REQUEST_TYPE))
        headers.putAll(mapOf(USER_AGENT_KEY to USER_AGENT))

        val response = Fuel.get(serviceBaseUrl + extractRequestType(endpoint))
            .header(headers)
            .response()
            .second

        if (response.statusCode > 299)
            return Passw0rdProtos.HttpError.parseFrom(response.data)

        return responseType.parserForType.parseFrom(response.data)
    }

    fun <I, O> firePost(
        data: I,
        endpoint: AvailableRequests,
        headers: MutableMap<String, String> = mutableMapOf(),
        authToken: String,
        responseParser: Parser<O>
    ): O where I : Message, O : Message {
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

    fun fireDelete(
        endpoint: AvailableRequests,
        headers: MutableMap<String, String> = mutableMapOf(),
        authToken: String,
        responseType: Message
    ): Message {
        headers.putAll(mapOf(APP_TOKEN_KEY to authToken))
        headers.putAll(mapOf(PROTO_REQUEST_TYPE_KEY to PROTO_REQUEST_TYPE))
        headers.putAll(mapOf(USER_AGENT_KEY to USER_AGENT))

        val response = Fuel.delete(serviceBaseUrl + extractRequestType(endpoint))
            .header(headers)
            .response()
            .second

        if (response.statusCode > 299)
            return Passw0rdProtos.HttpError.parseFrom(response.data)

        return responseType.parserForType.parseFrom(response.data)
    }

    private fun extractRequestType(availableRequests: AvailableRequests) =
        when (availableRequests) {
            AvailableRequests.ENROLL -> "/enroll"
            AvailableRequests.VERIFY_PASSWORD -> "/verify-password"
        }

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