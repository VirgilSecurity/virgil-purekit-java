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

import com.virgilsecurity.purekit.data.InvalidPasswordException
import com.virgilsecurity.purekit.data.InvalidProofException
import com.virgilsecurity.purekit.data.NoKeysFoundException
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos
import com.virgilsecurity.purekit.data.EnrollResult
import com.virgilsecurity.purekit.utils.PropertyManager
import com.virgilsecurity.purekit.utils.ProtocolUtils
import com.virgilsecurity.purekit.utils.ThreadUtils
import kotlinx.coroutines.future.await
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

/**
 * ProtocolTest class.
 */
class ProtocolTest {

    // HTC-1
    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    fun enroll_first_key(serverAddress: String, appToken: String, publicKey: String, secretKey: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken = "")

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = PurekitProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(2, enrollmentResponse.version)

        var accountKey: ByteArray? = null
        runBlocking {
            accountKey = protocol.verifyPassword(PASSWORD, enrollResult!!.enrollmentRecord).await()
        }
        assertNotNull(accountKey)
        assertArrayEquals(enrollResult!!.accountKey, accountKey!!)
    }

    // HTC-2
    @ParameterizedTest @MethodSource("testArguments")
    fun enroll_first_key_with_update_token(serverAddress: String,
                                           appToken: String,
                                           publicKey: String,
                                           secretKey: String,
                                           updateToken: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken)

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = PurekitProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(3, enrollmentResponse.version)

        var accountKey: ByteArray? = null
        runBlocking {
            accountKey = protocol.verifyPassword(PASSWORD, enrollResult!!.enrollmentRecord).await()
        }
        assertNotNull(accountKey)
        assertArrayEquals(enrollResult!!.accountKey, accountKey!!)
    }

    // HTC-3
    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    fun enroll_verify_wrong_pass(serverAddress: String, appToken: String, publicKey: String, secretKey: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken = "")

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = PurekitProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(2, enrollmentResponse.version)

        assertThrows<InvalidPasswordException> {
            runBlocking {
                protocol.verifyPassword(WRONG + PASSWORD, enrollResult!!.enrollmentRecord).await()
            }
        }
    }

    // HTC-4
    @ParameterizedTest @MethodSource("testArgumentsWithWrongKey")
    fun enroll_wrong_service_key(serverAddress: String,
                                 appToken: String,
                                 publicKey: String,
                                 publicKeyWrong: String,
                                 secretKey: String,
                                 updateToken: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken = "")

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = PurekitProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(2, enrollmentResponse.version)

        // Using wrong public key
        val protocolNew = ProtocolUtils.initProtocol(serverAddress, appToken, publicKeyWrong, secretKey, updateToken)

        assertThrows<InvalidProofException> {
            runBlocking {
                protocolNew.enrollAccount(PASSWORD).await()
            }
        }

        assertThrows<InvalidProofException> {
            runBlocking {
                protocolNew.verifyPassword(PASSWORD, enrollResult!!.enrollmentRecord).await()
            }
        }
    }

    // HTC-5
    @ParameterizedTest @MethodSource("testArguments")
    fun update_enrollment(serverAddress: String,
                          appToken: String,
                          publicKey: String,
                          secretKey: String,
                          updateToken: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken = "")

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = PurekitProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(2, enrollmentResponse.version)

        val protocolNew = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken)

        var record: ByteArray? = null
        runBlocking {
            record = RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord,
                                                          updateToken).await()
        }
        assertNotNull(record)

        val dbRecord = PurekitProtos.DatabaseRecord.parseFrom(record!!)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(3, dbRecord.version)

        var accountKey: ByteArray? = null
        runBlocking {
            accountKey = protocol.verifyPassword(PASSWORD, enrollResult!!.enrollmentRecord).await()
        }
        assertNotNull(accountKey)
        assertEquals(ACCOUNT_KEY_SIZE, accountKey!!.size)
        assertArrayEquals(enrollResult!!.accountKey, accountKey)

        var accountKeyTwo: ByteArray? = null
        runBlocking {
            accountKeyTwo = protocolNew.verifyPassword(PASSWORD, record!!).await()
        }
        assertNotNull(accountKeyTwo)
        assertArrayEquals(enrollResult!!.accountKey, accountKeyTwo)
    }

    // HTC-6
    @ParameterizedTest @MethodSource("testArguments")
    fun update_on_already_migrated(serverAddress: String,
                                   appToken: String,
                                   publicKey: String,
                                   secretKey: String,
                                   updateToken: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken)

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = PurekitProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(3, enrollmentResponse.version)

        assertThrows<IllegalArgumentException> {
            runBlocking {
                RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord,
                                                     updateToken)
                        .await()
            }
        }
    }

    // HTC-7
    @ParameterizedTest @MethodSource("testArguments")
    fun update_with_wrong_version(serverAddress: String,
                                  appToken: String,
                                  publicKey: String,
                                  secretKey: String,
                                  updateToken: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken)

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = PurekitProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)
        val wrongEnrollmentResponse = PurekitProtos.EnrollmentResponse.newBuilder()
                .setResponse(enrollmentResponse.response)
                .setVersion(1)
                .build()

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(3, enrollmentResponse.version)

        assertThrows<IllegalArgumentException> {
            runBlocking {
                RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord,
                                                     updateToken)
                        .await()
            }
        }

        assertThrows<NoKeysFoundException> {
            runBlocking {
                protocol.verifyPassword(PASSWORD, wrongEnrollmentResponse.toByteArray()).await()
            }
        }
    }

    @ParameterizedTest @MethodSource("testArguments")
    fun enroll_verify_update_full_flow(serverAddress: String,
                                       appToken: String,
                                       publicKey: String,
                                       secretKey: String,
                                       updateToken: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken = "")

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        assertTrue(enrollResult!!.enrollmentRecord.isNotEmpty())
        assertTrue(enrollResult!!.accountKey.size == 32)

        var verifyKey: ByteArray? = null
        runBlocking {
            verifyKey = protocol.verifyPassword(PASSWORD, enrollResult!!.enrollmentRecord).await()
        }
        assertArrayEquals(enrollResult!!.accountKey, verifyKey)

        var failed = false
        runBlocking {
            try {
                protocol.verifyPassword("$WRONG $PASSWORD", enrollResult!!.enrollmentRecord).await()
            } catch (e: InvalidPasswordException) {
                failed = true
            }
        }
        assertTrue(failed)

        // After token rotate
        val protocolNew = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken)

        var newRecord: ByteArray? = null
        runBlocking {
            newRecord = RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord,
                                                             updateToken).await()
        }
        assertNotNull(newRecord)

        var verifyKeyNew: ByteArray? = null
        runBlocking {
            verifyKeyNew = protocolNew.verifyPassword(PASSWORD, newRecord!!).await()
        }
        assertArrayEquals(enrollResult!!.accountKey, verifyKeyNew)
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    fun encrypt_decrypt(serverAddress: String, appToken: String, publicKey: String, secretKey: String) {
        ThreadUtils.pause()

        val protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken = "")

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        assertTrue(enrollResult!!.enrollmentRecord.isNotEmpty())
        assertTrue(enrollResult!!.accountKey.size == 32)

        val encryptedData = protocol.encrypt(TEXT.toByteArray(), enrollResult!!.accountKey)
        assertNotNull(encryptedData)

        val decryptedData = protocol.decrypt(encryptedData, enrollResult!!.accountKey)
        assertNotNull(decryptedData)
        assertEquals(TEXT, String(decryptedData))
    }

    companion object {
        const val WRONG = "WRONG"
        const val PASSWORD = "p@ssw0Rd"
        private const val ACCOUNT_KEY_SIZE = 32

        const val TEXT = "The best text ever."

        @JvmStatic fun testArgumentsNoToken() = listOf(
                Arguments.of(PropertyManager.virgilPheServerAddress,
                             PropertyManager.virgilAppToken,
                             PropertyManager.virgilPublicKeyNew,
                             PropertyManager.virgilSecretKeyNew)
        )

        @JvmStatic fun testArguments() = listOf(
                Arguments.of(PropertyManager.virgilPheServerAddress,
                             PropertyManager.virgilAppToken,
                             PropertyManager.virgilPublicKeyNew,
                             PropertyManager.virgilSecretKeyNew,
                             PropertyManager.virgilUpdateTokenNew)
        )

        @JvmStatic fun testArgumentsWithWrongKey() = listOf(
                Arguments.of(PropertyManager.virgilPheServerAddress,
                             PropertyManager.virgilAppToken,
                             PropertyManager.virgilPublicKeyNew,
                             PropertyManager.virgilPublicKeyWrong,
                             PropertyManager.virgilSecretKeyNew,
                             PropertyManager.virgilUpdateTokenNew)
        )
    }
}