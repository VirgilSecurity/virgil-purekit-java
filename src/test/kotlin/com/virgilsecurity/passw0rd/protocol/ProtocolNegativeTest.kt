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

package com.virgilsecurity.passw0rd.protocol

import com.virgilsecurity.passw0rd.Protocol
import com.virgilsecurity.passw0rd.ProtocolContext
import com.virgilsecurity.passw0rd.client.HttpClientProtobuf
import com.virgilsecurity.passw0rd.data.InvalidProtobufType
import com.virgilsecurity.passw0rd.data.ProtocolException
import com.virgilsecurity.passw0rd.utils.PropertyManager
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.random.Random

/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    2019-01-17
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

/**
 * ProtocolNegativeTest class.
 */
class ProtocolNegativeTest {

    private lateinit var context: ProtocolContext
    private lateinit var protocol: Protocol

    @BeforeEach fun setup() {
        context = ProtocolContext.create(
            PropertyManager.appToken,
            PropertyManager.publicKey,
            PropertyManager.secretKey,
            ""
        )
        Assertions.assertNotNull(context)

        protocol = Protocol(context, HttpClientProtobuf(PropertyManager.serverAddress))
    }

    @Test fun context_app_token_wrong() {
        context = ProtocolContext.create(
            WRONG_CRED,
            PropertyManager.publicKey,
            PropertyManager.secretKey,
            ""
        )
        Assertions.assertNotNull(context)

        protocol = Protocol(context, HttpClientProtobuf(PropertyManager.serverAddress))

        runBlocking {
            try {
                protocol.enrollAccount(PASSWORD).await()
            } catch (t: Throwable) {
                assertTrue(t is ProtocolException)
            }
        }
    }

    @Test fun context_public_key_wrong() {
        assertThrows<IllegalArgumentException> {
            context = ProtocolContext.create(
                PropertyManager.appToken,
                WRONG_CRED,
                PropertyManager.secretKey,
                ""
            )
        }
    }

    @Test fun context_secret_key_wrong() {
        assertThrows<IllegalArgumentException> {
            context = ProtocolContext.create(
                PropertyManager.appToken,
                PropertyManager.publicKey,
                WRONG_CRED,
                ""
            )
        }
    }

    @Test fun context_update_token_wrong() {
        assertThrows<IllegalArgumentException> {
            context = ProtocolContext.create(
                PropertyManager.appToken,
                PropertyManager.publicKey,
                PropertyManager.secretKey,
                WRONG_CRED
            )
        }
    }

    @Test fun enroll_with_empty_pass() {
        runBlocking {
            try {
                protocol.enrollAccount("").await()
            } catch (t: Throwable) {
                assertTrue(t is IllegalArgumentException)
            }
        }
    }

    @Test fun verify_with_empty_pass() {
        runBlocking {
            try {
                protocol.verifyPassword("", ByteArray(0)).await()
            } catch (t: Throwable) {
                assertTrue(t is IllegalArgumentException)
            }
        }
    }

    @Test fun verify_with_empty_record() {
        runBlocking {
            try {
                protocol.verifyPassword(PASSWORD, ByteArray(0)).await()
            } catch (t: Throwable) {
                assertTrue(t is IllegalArgumentException)
            }
        }
    }

    @Test fun verify_with_wrong_record() {
        runBlocking {
            try {
                protocol.verifyPassword(PASSWORD, Random.nextBytes(RANDOM_BYTES_SIZE)).await()
            } catch (t: Throwable) {
                assertTrue(t is InvalidProtobufType)
            }
        }
    }

    @Test fun update_token_empty() {
        var failed = false
        runBlocking {
            try {
                protocol.updateEnrollmentRecord(Random.nextBytes(RANDOM_BYTES_SIZE)).await()
            } catch (e: IllegalArgumentException) {
                failed = true
            }
        }
        assertTrue(failed)
    }

    @Test fun update_token_empty_record() {
        var failed = false
        runBlocking {
            try {
                protocol.updateEnrollmentRecord(ByteArray(0)).await()
            } catch (e: IllegalArgumentException) {
                failed = true
            }
        }
        assertTrue(failed)
    }

    @Test fun update_with_wrong_record() {
        context = ProtocolContext.create(
            PropertyManager.appToken,
            PropertyManager.publicKey,
            PropertyManager.secretKey,
            PropertyManager.updateToken
        )
        protocol = Protocol(context, HttpClientProtobuf(PropertyManager.serverAddress))

        runBlocking {
            try {
                protocol.updateEnrollmentRecord(Random.nextBytes(RANDOM_BYTES_SIZE)).await()
            } catch (t: Throwable) {
                assertTrue(t is InvalidProtobufType)
            }
        }
    }

    companion object {
        const val RANDOM_BYTES_SIZE = 32

        private const val WRONG_CRED = "WRONG_CRED"
        private const val PASSWORD = "PASSWORD"
    }
}