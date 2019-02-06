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
import com.google.protobuf.InvalidProtocolBufferException
import com.virgilsecurity.passw0rd.client.HttpClientProtobuf
import com.virgilsecurity.passw0rd.data.*
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos
import com.virgilsecurity.passw0rd.utils.EnrollResult
import com.virgilsecurity.passw0rd.utils.requires
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.future.asCompletableFuture
import virgil.crypto.phe.PheCipher
import virgil.crypto.phe.PheClient
import virgil.crypto.phe.PheException
import java.util.concurrent.CompletableFuture

/**
 * Protocol class implements passw0rd client-server protocol.
 */
class Protocol @JvmOverloads constructor(
        protocolContext: ProtocolContext,
        private val httpClient: HttpClientProtobuf = HttpClientProtobuf()
) {

    private val appToken: String = protocolContext.appToken
    private val pheClients: Map<Int, PheClient> = protocolContext.pheClients
    private val currentVersion: Int = protocolContext.version
    private val pheCipher: PheCipher by lazy { PheCipher().apply { setupDefaults() } }

    /**
     * This function requests pseudo-random data from server and uses it to protect [password] and data encryption key.
     *
     * @throws IllegalArgumentException
     * @throws ProtocolException
     * @throws PheException
     */
    @Throws(IllegalArgumentException::class, ProtocolException::class, PheException::class)
    fun enrollAccount(password: String): CompletableFuture<EnrollResult> = GlobalScope.async {
        requires(password.isNotBlank(), "password")

        with(Passw0rdProtos.EnrollmentRequest.newBuilder().setVersion(currentVersion).build()) {
            with(httpClient.firePost(
                    this,
                    HttpClientProtobuf.AvailableRequests.ENROLL,
                    authToken = appToken,
                    responseParser = Passw0rdProtos.EnrollmentResponse.parser()

            ).let { response ->
                val pheClient = pheClients[response.version]
                        ?: throw NoKeysFoundException("Unable to find keys corresponding to record's version $version.")
                   
                val enrollResult = try {
                    pheClient.enrollAccount(response.response.toByteArray(), password.toByteArray())
                } catch (exception: PheException) {
                    throw InvalidProofException()
                }

                val enrollmentRecord = Passw0rdProtos.DatabaseRecord
                        .newBuilder()
                        .setVersion(currentVersion)
                        .setRecord(ByteString.copyFrom(enrollResult.enrollmentRecord))
                        .build()
                        .toByteArray()

                EnrollResult(enrollmentRecord, enrollResult.accountKey)
            }
        }
    }.asCompletableFuture()

    /**
     * This function verifies a [password] against [enrollmentRecord] using passw0rd service.
     *
     * @throws IllegalArgumentException
     * @throws ProtocolException
     * @throws PheException
     * @throws InvalidPasswordException
     * @throws InvalidProtobufTypeException
     */
    @Throws(
            IllegalArgumentException::class,
            ProtocolException::class,
            PheException::class,
            InvalidPasswordException::class,
            InvalidProtobufTypeException::class
    )
    fun verifyPassword(password: String, enrollmentRecord: ByteArray): CompletableFuture<ByteArray> = GlobalScope.async {
        requires(password.isNotBlank(), "password")
        requires(enrollmentRecord.isNotEmpty(), "enrollmentRecord")

        val (version, record) = try {
            with(Passw0rdProtos.DatabaseRecord.parseFrom(enrollmentRecord)) {
                version to record.toByteArray()
            }
        } catch (e: InvalidProtocolBufferException) {
            throw InvalidProtobufTypeException()
        }

        val pheClient = pheClients[version]
                ?: throw NoKeysFoundException("Unable to find keys corresponding to record's version $version.")

        val request = pheClient.createVerifyPasswordRequest(password.toByteArray(), record)

        val verifyPasswordRequest = Passw0rdProtos.VerifyPasswordRequest
                .newBuilder()
                .setVersion(version)
                .setRequest(ByteString.copyFrom(request))
                .build()

        with(httpClient.firePost(
                verifyPasswordRequest,
                HttpClientProtobuf.AvailableRequests.VERIFY_PASSWORD,
                authToken = appToken,
                responseParser = Passw0rdProtos.VerifyPasswordResponse.parser()
        )) {
            val key = try {
                pheClient.checkResponseAndDecrypt(password.toByteArray(), record, response.toByteArray())
            } catch (exception: PheException) {
                throw InvalidProofException()
            }
            if (key.isEmpty()) {
                throw InvalidPasswordException("The password you specified is wrong.")
            }
            key
        }
    }.asCompletableFuture()

    /**
     * This function encrypts provided [data] using [accountKey].
     *
     * @throws IllegalArgumentException
     * @throws PheException
     */
    @Throws(IllegalArgumentException::class, PheException::class)
    fun encrypt(data: ByteArray, accountKey: ByteArray): ByteArray {
        requires(data.isNotEmpty(), "data")
        requires(accountKey.isNotEmpty(), "accountKey")

        return pheCipher.encrypt(data, accountKey)
    }

    /**
     * This function decrypts provided [data] using [accountKey].
     *
     * @throws IllegalArgumentException
     * @throws PheException
     */
    @Throws(IllegalArgumentException::class, PheException::class)
    fun decrypt(data: ByteArray, accountKey: ByteArray): ByteArray {
        requires(data.isNotEmpty(), "data")
        requires(accountKey.isNotEmpty(), "accountKey")

        return pheCipher.decrypt(data, accountKey)
    }
}