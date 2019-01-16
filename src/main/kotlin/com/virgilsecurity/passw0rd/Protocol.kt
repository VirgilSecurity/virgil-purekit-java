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
import com.virgilsecurity.passw0rd.client.HttpClientProtobuf
import com.virgilsecurity.passw0rd.data.InvalidPasswordException
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import virgil.crypto.phe.PheClient
import java.lang.IllegalArgumentException

/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    12/14/18
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

/**
 * Protocol class.
 */
class Protocol(protocolContext: ProtocolContext, val httpClient: HttpClientProtobuf = HttpClientProtobuf()) {

    val appToken: String = protocolContext.appToken
    val pheClient: PheClient = protocolContext.pheClient
    val currentVersion: Int = protocolContext.version
    val updateToken: Passw0rdProtos.VersionedUpdateToken? = protocolContext.updateToken
    lateinit var pheCipher: PheCipherStub

    fun enrollAccount(password: String): Deferred<Pair<ByteArray, ByteArray>> = GlobalScope.async {
        Passw0rdProtos.EnrollmentRequest.newBuilder().setVersion(currentVersion).build().run {
            httpClient.firePost(
                this,
                HttpClientProtobuf.AvailableRequests.ENROLL,
                authToken = appToken,
                responseParser = Passw0rdProtos.EnrollmentResponse.parser()
            ).let { response ->
                val record = pheClient.enrollAccount(response.response.toByteArray(), password.toByteArray())

                val enrollmentRecord = Passw0rdProtos.DatabaseRecord
                    .newBuilder()
                    .setVersion(version)
                    .setRecord(ByteString.copyFrom(record.enrollmentRecord))
                    .build()
                    .toByteArray()

                Pair(enrollmentRecord, record.accountKey)
            }
        }
    }

    fun verifyPassword(password: String, enrollmentRecord: ByteArray): Deferred<ByteArray> = GlobalScope.async {
        val (version, record) = Passw0rdProtos.DatabaseRecord.parseFrom(enrollmentRecord).let {
            it.version to it.record.toByteArray()
        }

        val request = pheClient.createVerifyPasswordRequest(password.toByteArray(), record)

        val verifyPasswordRequest = Passw0rdProtos.VerifyPasswordRequest
            .newBuilder()
            .setVersion(version)
            .setRequest(ByteString.copyFrom(request))
            .build()

        httpClient.firePost(verifyPasswordRequest,
                            HttpClientProtobuf.AvailableRequests.VERIFY_PASSWORD,
                            authToken = appToken,
                            responseParser = Passw0rdProtos.VerifyPasswordResponse.parser()).let {
            val key = pheClient.checkResponseAndDecrypt(password.toByteArray(), record, it.response.toByteArray())

            if (key.isEmpty())
                throw InvalidPasswordException("The password you specified is wrong.")

            key
        }
    }

    fun updateEnrollmentRecord(passwordRecord: ByteArray): Deferred<ByteArray> = GlobalScope.async {
        if (updateToken?.updateToken!!.isEmpty) // TODO test nullable token
            throw IllegalArgumentException("The update token can not be empty")

        val (version, record) = Passw0rdProtos.DatabaseRecord.parseFrom(passwordRecord).let {// TODO check record variable usage
            it.version to it.record.toByteArray()
        }

        if (version == currentVersion)
            return@async passwordRecord

        if (version > currentVersion)
            throw IllegalArgumentException("Record's version is greater than protocol's version")

        pheClient.updateEnrollmentRecord(passwordRecord, updateToken.updateToken.toByteArray())
    }

    fun encrypt(text: String, accountKey: String): String =
        pheCipher.encrypt(text, accountKey) // TODO add real encrypt and decrypt

    fun decrypt(text: String, accountKey: String): String =
        pheCipher.decrypt(text, accountKey)
}