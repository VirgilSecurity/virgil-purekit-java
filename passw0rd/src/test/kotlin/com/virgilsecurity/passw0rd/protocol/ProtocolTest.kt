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

import com.virgilsecurity.passw0rd.client.HttpClientProtobuf
import com.virgilsecurity.passw0rd.data.InvalidPasswordException
import com.virgilsecurity.passw0rd.data.InvalidProofException
import com.virgilsecurity.passw0rd.data.NoKeysFoundException
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos
import com.virgilsecurity.passw0rd.utils.EnrollResult
import com.virgilsecurity.passw0rd.utils.PropertyManager
import com.virgilsecurity.passw0rd.utils.ThreadUtils
import kotlinx.coroutines.future.await
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Created by: Danylo Oliinyk.
 * On 01/04/2019 at Virgil Security.
 */

/**
 * ProtocolTest class.
 */
class ProtocolTest {

    private val propertyManager = PropertyManager

    private lateinit var context: ProtocolContext
    private lateinit var protocol: Protocol

    @BeforeEach fun setup() {
        context = ProtocolContext.create(
                PropertyManager.appToken,
                PropertyManager.publicKeyNew,
                PropertyManager.secretKeyNew,
                ""
        )
        assertNotNull(context)

        protocol = Protocol(context,
                            HttpClientProtobuf(PropertyManager.serverAddress))
    }

    // HTC-1
    @Test fun enroll_first_key() {
        ThreadUtils.pause()

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = Passw0rdProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

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
    @Test fun enroll_first_key_with_update_token() {
        ThreadUtils.pause()

        val protocolContext = ProtocolContext.create(
                propertyManager.appToken,
                propertyManager.publicKeyNew,
                propertyManager.secretKeyNew,
                propertyManager.updateTokenNew
        )

        val protocol = Protocol(protocolContext,
                                HttpClientProtobuf(PropertyManager.serverAddress))

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = Passw0rdProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

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
    @Test fun enroll_verify_wrong_pass() {
        ThreadUtils.pause()

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = Passw0rdProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(2, enrollmentResponse.version)

        assertThrows<InvalidPasswordException> {
            runBlocking {
                protocol.verifyPassword(WRONG + PASSWORD, enrollResult!!.enrollmentRecord).await()
            }
        }
    }

    // HTC-4
    @Test fun enroll_wrong_service_key() {
        ThreadUtils.pause()

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = Passw0rdProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(2, enrollmentResponse.version)

        val protocolContextNew = ProtocolContext.create(
                propertyManager.appToken,
                propertyManager.publicKeyWrong, // Wrong public key
                propertyManager.secretKeyNew,
                propertyManager.updateTokenNew
        )

        val protocolNew = Protocol(protocolContextNew,
                                   HttpClientProtobuf(PropertyManager.serverAddress))

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
    @Test fun update_enrollment() {
        ThreadUtils.pause()

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = Passw0rdProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(2, enrollmentResponse.version)

        val protocolContextNew = ProtocolContext.create(
                propertyManager.appToken,
                propertyManager.publicKeyNew,
                propertyManager.secretKeyNew,
                propertyManager.updateTokenNew
        )

        val protocolNew = Protocol(protocolContextNew,
                                   HttpClientProtobuf(PropertyManager.serverAddress))

        var record: ByteArray? = null
        runBlocking {
            record = RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord,
                                                          PropertyManager.updateTokenNew).await()
        }
        assertNotNull(record)

        val dbRecord = Passw0rdProtos.DatabaseRecord.parseFrom(record!!)

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
    @Test fun update_on_already_migrated() {
        ThreadUtils.pause()

        val protocolContext = ProtocolContext.create(
                propertyManager.appToken,
                propertyManager.publicKeyNew,
                propertyManager.secretKeyNew,
                propertyManager.updateTokenNew
        )

        val protocol = Protocol(protocolContext,
                                HttpClientProtobuf(PropertyManager.serverAddress))

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = Passw0rdProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(3, enrollmentResponse.version)

        assertThrows<IllegalArgumentException> {
            runBlocking {
                RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord, PropertyManager.updateTokenNew)
                        .await()
            }
        }
    }

    // HTC-7
    @Test fun update_with_wrong_version() {
        ThreadUtils.pause()

        val protocolContext = ProtocolContext.create(
                propertyManager.appToken,
                propertyManager.publicKeyNew,
                propertyManager.secretKeyNew,
                propertyManager.updateTokenNew
        )

        val protocol = Protocol(protocolContext,
                                HttpClientProtobuf(PropertyManager.serverAddress))

        var enrollResult: EnrollResult? = null
        runBlocking {
            enrollResult = protocol.enrollAccount(PASSWORD).await()
        }
        assertNotNull(enrollResult)
        val enrollmentResponse = Passw0rdProtos.EnrollmentResponse.parseFrom(enrollResult!!.enrollmentRecord)
        val wrongEnrollmentResponse = Passw0rdProtos.EnrollmentResponse.newBuilder()
                .setResponse(enrollmentResponse.response)
                .setVersion(1)
                .build()

        assertEquals(ACCOUNT_KEY_SIZE, enrollResult!!.accountKey.size)
        assertEquals(3, enrollmentResponse.version)

        assertThrows<IllegalArgumentException> {
            runBlocking {
                RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord, PropertyManager.updateTokenNew)
                        .await()
            }
        }

        assertThrows<NoKeysFoundException> {
            runBlocking {
                protocol.verifyPassword(PASSWORD, wrongEnrollmentResponse.toByteArray()).await()
            }
        }
    }

    @Test fun enroll_verify_update_full_flow() {
        ThreadUtils.pause()

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
        context = ProtocolContext.create(
                PropertyManager.appToken,
                PropertyManager.publicKeyNew,
                PropertyManager.secretKeyNew,
                PropertyManager.updateTokenNew
        )
        assertNotNull(context)

        protocol = Protocol(context,
                            HttpClientProtobuf(PropertyManager.serverAddress))

        var newRecord: ByteArray? = null
        runBlocking {
            newRecord = RecordUpdater.updateEnrollmentRecord(enrollResult!!.enrollmentRecord,
                                                             PropertyManager.updateTokenNew).await()
        }
        assertNotNull(newRecord)

        var verifyKeyNew: ByteArray? = null
        runBlocking {
            verifyKeyNew = protocol.verifyPassword(PASSWORD, newRecord!!).await()
        }
        assertArrayEquals(enrollResult!!.accountKey, verifyKeyNew)
    }

    @Test fun encrypt_decrypt() {
        ThreadUtils.pause()

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
    }
}