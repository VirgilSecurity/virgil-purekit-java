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

import com.virgilsecurity.passw0rd.utils.PropertyManager
import com.virgilsecurity.passw0rd.Protocol
import com.virgilsecurity.passw0rd.ProtocolContext
import com.virgilsecurity.passw0rd.client.HttpClientProtobuf
import com.virgilsecurity.passw0rd.data.InvalidPasswordException
import com.virgilsecurity.passw0rd.utils.EnrollResult
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    2019-01-04
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

/**
 * ProtocolTest class.
 */
class ProtocolTest {

    private lateinit var context: ProtocolContext
    private lateinit var protocol: Protocol

    @BeforeEach fun setup() {
        context = ProtocolContext.create(
                PropertyManager.appToken,
                PropertyManager.publicKey,
                PropertyManager.secretKey,
                ""
        )
        assertNotNull(context)

        protocol = Protocol(context, HttpClientProtobuf(PropertyManager.serverAddress))
    }

    @Test fun enroll_verify_update_full_flow() {
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
                PropertyManager.publicKey,
                PropertyManager.secretKey,
                PropertyManager.updateToken
        )
        assertNotNull(context)

        protocol = Protocol(context, HttpClientProtobuf(PropertyManager.serverAddress))

        var newRecord: ByteArray? = null
        runBlocking {
            newRecord = protocol.updateEnrollmentRecord(enrollResult!!.enrollmentRecord).await()
        }
        assertNotNull(newRecord)

        var verifyKeyNew: ByteArray? = null
        runBlocking {
            verifyKeyNew = protocol.verifyPassword(PASSWORD, newRecord!!).await()
        }
        assertArrayEquals(enrollResult!!.accountKey, verifyKeyNew)
    }

    @Test fun encrypt_decrypt() {
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

        const val TEXT = "The best text ever."
    }
}