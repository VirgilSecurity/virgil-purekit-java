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

package com.virgilsecurity.purekit.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.virgilsecurity.purekit.data.InvalidPasswordException;
import com.virgilsecurity.purekit.data.InvalidProtobufTypeException;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.EnrollResult;
import com.virgilsecurity.purekit.utils.PropertyManager;
import com.virgilsecurity.purekit.utils.ProtocolUtils;
import com.virgilsecurity.purekit.utils.ThreadUtils;
import java.util.concurrent.ExecutionException;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * ProtocolTestJava class.
 */
class ProtocolTestJava {

    private static final String WRONG = "WRONG";
    private static final String PASSWORD = "p@ssw0Rd";
    private static final String TEXT = "The best text ever.";
    private static final int ACCOUNT_KEY_SIZE = 32;

    @ParameterizedTest @MethodSource("testArguments")
    void enroll_verify_update_full_flow(String serverAddress,
                                        String appToken,
                                        String publicKey,
                                        String secretKey,
                                        String updateToken)
            throws ProtocolException,
            ExecutionException,
            InterruptedException,
            InvalidProtobufTypeException,
            InvalidPasswordException {
        ThreadUtils.pause();

        Protocol protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, "");

        EnrollResult enrollResult = protocol.enrollAccount(PASSWORD).get();

        assertNotNull(enrollResult);
        assertTrue(enrollResult.getEnrollmentRecord().length != 0); // Not empty
        assertEquals(ACCOUNT_KEY_SIZE, enrollResult.getAccountKey().length);

        byte[] verifyKey = protocol.verifyPassword(PASSWORD, enrollResult.getEnrollmentRecord()).get();
        assertArrayEquals(enrollResult.getAccountKey(), verifyKey);

        boolean failed = false;
        try {
            protocol.verifyPassword(WRONG + PASSWORD, enrollResult.getEnrollmentRecord()).get();
        } catch (ExecutionException t) {
            if (t.getCause() instanceof InvalidPasswordException)
                failed = true;
        }
        assertTrue(failed);

        // After token rotate
        Protocol protocolNew = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, updateToken);

        byte[] newRecord;
        newRecord = RecordUpdater.updateEnrollmentRecord(enrollResult.getEnrollmentRecord(), updateToken).get();
        assertNotNull(newRecord);

        byte[] verifyKeyNew;
        verifyKeyNew = protocolNew.verifyPassword(PASSWORD, newRecord).get();
        assertArrayEquals(enrollResult.getAccountKey(), verifyKeyNew);
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encrypt_decrypt(String serverAddress,
                         String appToken,
                         String publicKey,
                         String secretKey) throws InterruptedException, ProtocolException, ExecutionException {
        ThreadUtils.pause();

        Protocol protocol = ProtocolUtils.initProtocol(serverAddress, appToken, publicKey, secretKey, "");

        EnrollResult enrollResult = protocol.enrollAccount(PASSWORD).get();
        assertNotNull(enrollResult);
        assertTrue(enrollResult.getEnrollmentRecord().length != 0); // Not empty
        assertEquals(ACCOUNT_KEY_SIZE, enrollResult.getAccountKey().length);

        byte[] encryptedData = protocol.encrypt(TEXT.getBytes(), enrollResult.getAccountKey());
        assertNotNull(encryptedData);

        byte[] decryptedData = protocol.decrypt(encryptedData, enrollResult.getAccountKey());
        assertNotNull(decryptedData);
        assertEquals(TEXT, new String(decryptedData));
    }

    private static Stream<Arguments> testArgumentsNoToken() {
        return Stream.of(
                Arguments.of(PropertyManager.getPheServiceAddress(),
                             PropertyManager.getAppToken(),
                             PropertyManager.getPhePublicKeyNew(),
                             PropertyManager.getPheSecretKeyNew())
        );
    }

    private static Stream<Arguments> testArguments() {
        return Stream.of(
                Arguments.of(PropertyManager.getPheServiceAddress(),
                             PropertyManager.getAppToken(),
                             PropertyManager.getPhePublicKeyOld(),
                             PropertyManager.getPheSecretKeyOld(),
                             PropertyManager.getPheUpdateToken())
        );
    }
}
