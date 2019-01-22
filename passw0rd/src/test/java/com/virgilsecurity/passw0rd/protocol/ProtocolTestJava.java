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

package com.virgilsecurity.passw0rd.protocol;

/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    2019-01-22
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.virgilsecurity.passw0rd.client.HttpClientProtobuf;
import com.virgilsecurity.passw0rd.data.InvalidPasswordException;
import com.virgilsecurity.passw0rd.data.InvalidProofException;
import com.virgilsecurity.passw0rd.data.NoKeysFoundException;
import com.virgilsecurity.passw0rd.data.ProtocolException;
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos;
import com.virgilsecurity.passw0rd.utils.EnrollResult;
import com.virgilsecurity.passw0rd.utils.PropertyManager;
import com.virgilsecurity.passw0rd.utils.ThreadUtils;
import kotlinx.coroutines.Deferred;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * ProtocolTestJava class.
 */
class ProtocolTestJava {

//    private static final String WRONG = "WRONG";
//    private static final String PASSWORD = "p@ssw0Rd";
//    private static final int ACCOUNT_KEY_SIZE = 32;
//    private static final String TEXT = "The best text ever.";
//
//    private ProtocolContext context;
//    private Protocol protocol;
//
//    @BeforeEach void setup() {
//        context = ProtocolContext.create(
//                PropertyManager.getAppToken(),
//                PropertyManager.getPublicKeyNew(),
//                PropertyManager.getSecretKeyNew(),
//                ""
//        );
//        assertNotNull(context);
//
//        protocol = new Protocol(context, new HttpClientProtobuf(PropertyManager.getServerAddress()));
//    }
//
//    @Test void enroll_verify_update_full_flow() throws ProtocolException {
//        ThreadUtils.pause();
//
//        EnrollResult enrollResult = null;
//
//        Deferred<EnrollResult> deferredResult = protocol.enrollAccount(PASSWORD);
//            enrollResult = deferredResult.();
//
//        assertNotNull(enrollResult)
//        assertTrue(enrollResult !!.enrollmentRecord.isNotEmpty())
//        assertTrue(enrollResult !!.accountKey.size == 32)
//
//        var verifyKey:ByteArray ? = null
//        runBlocking {
//            verifyKey = protocol.verifyPassword(PASSWORD, enrollResult !!.enrollmentRecord).await()
//        }
//        assertArrayEquals(enrollResult !!.accountKey, verifyKey)
//
//        var failed = false
//        runBlocking {
//            try {
//                protocol.verifyPassword("$WRONG $PASSWORD", enrollResult !!.enrollmentRecord).await()
//            } catch (e:InvalidPasswordException){
//                failed = true
//            }
//        }
//        assertTrue(failed)
//
//        // After token rotate
//        context = ProtocolContext.create(
//                PropertyManager.appToken,
//                PropertyManager.publicKeyNew,
//                PropertyManager.secretKeyNew,
//                PropertyManager.updateTokenNew
//        )
//        assertNotNull(context)
//
//        protocol = Protocol(context,
//                            HttpClientProtobuf(PropertyManager.serverAddress))
//
//        var newRecord:ByteArray ? = null
//        runBlocking {
//            newRecord = RecordUpdater.updateEnrollmentRecord(enrollResult !!.enrollmentRecord,
//                    PropertyManager.updateTokenNew).await()
//        }
//        assertNotNull(newRecord)
//
//        var verifyKeyNew:ByteArray ? = null
//        runBlocking {
//            verifyKeyNew = protocol.verifyPassword(PASSWORD, newRecord !!).await()
//        }
//        assertArrayEquals(enrollResult !!.accountKey, verifyKeyNew)
//    }
//
//    @Test fun encrypt_decrypt() {
//        ThreadUtils.pause()
//
//        var enrollResult:EnrollResult ? = null
//        runBlocking {
//            enrollResult = protocol.enrollAccount(PASSWORD).await()
//        }
//        assertNotNull(enrollResult)
//        assertTrue(enrollResult !!.enrollmentRecord.isNotEmpty())
//        assertTrue(enrollResult !!.accountKey.size == 32)
//
//        val encryptedData = protocol.encrypt(TEXT.toByteArray(), enrollResult !!.accountKey)
//        assertNotNull(encryptedData)
//
//        val decryptedData = protocol.decrypt(encryptedData, enrollResult !!.accountKey)
//        assertNotNull(decryptedData)
//        assertEquals(TEXT, String(decryptedData))
//    }
}
