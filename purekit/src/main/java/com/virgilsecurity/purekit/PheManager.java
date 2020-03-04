/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

package com.virgilsecurity.purekit;

import com.google.protobuf.ByteString;
import com.virgilsecurity.crypto.phe.PheClient;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
import com.virgilsecurity.crypto.phe.PheClientRotateKeysResult;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.client.HttpPheClient;
import com.virgilsecurity.purekit.exception.PureCryptoException;
import com.virgilsecurity.purekit.exception.PureException;
import com.virgilsecurity.purekit.exception.PureLogicException;
import com.virgilsecurity.purekit.model.UserRecord;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.utils.ValidationUtils;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;

class PheManager {
    private final VirgilCrypto crypto;
    private final int currentVersion;
    private final PheClient currentClient;
    private final byte[] updateToken;
    private final PheClient previousClient;
    private final HttpPheClient httpClient;

    public PheManager(PureContext context) throws PureCryptoException {
        try {
            this.crypto = context.getCrypto();

            this.currentClient = new PheClient();
            this.currentClient.setOperationRandom(this.crypto.getRng());
            this.currentClient.setRandom(this.crypto.getRng());

            if (context.getUpdateToken() != null) {
                this.currentVersion = context.getPublicKey().getVersion() + 1;
                this.updateToken = context.getUpdateToken().getPayload1();
                this.previousClient = new PheClient();
                this.previousClient.setOperationRandom(this.crypto.getRng());
                this.previousClient.setRandom(this.crypto.getRng());
                this.previousClient.setKeys(context.getSecretKey().getPayload1(),
                        context.getPublicKey().getPayload1());

                PheClientRotateKeysResult rotateKeysResult = this.previousClient.rotateKeys(context.getUpdateToken().getPayload1());

                this.currentClient.setKeys(rotateKeysResult.getNewClientPrivateKey(),
                        rotateKeysResult.getNewServerPublicKey());
            } else {
                this.currentVersion = context.getPublicKey().getVersion();
                this.updateToken = null;
                this.currentClient.setKeys(context.getSecretKey().getPayload1(),
                        context.getPublicKey().getPayload1());
                this.previousClient = null;
            }

            this.httpClient = context.getPheClient();
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    private PheClient getPheClient(int pheVersion) throws NullPointerException {
        if (this.currentVersion == pheVersion) {
            return this.currentClient;
        } else if (this.currentVersion == pheVersion + 1) {
            return this.previousClient;
        } else {
            throw new NullPointerException("pheClient");
        }
    }

    byte[] computePheKey(UserRecord userRecord, String password) throws PureException {
        byte[] passwordHash = crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

        return computePheKey(userRecord, passwordHash);
    }

    byte[] computePheKey(UserRecord userRecord, byte[] passwordHash) throws PureException {

        try {
            PheClient client = getPheClient(userRecord.getRecordVersion());

            byte[] pheVerifyRequest = client.createVerifyPasswordRequest(passwordHash,
                    userRecord.getPheRecord());

            PurekitProtos.VerifyPasswordRequest request = PurekitProtos.VerifyPasswordRequest
                    .newBuilder()
                    .setVersion(userRecord.getRecordVersion())
                    .setRequest(ByteString.copyFrom(pheVerifyRequest))
                    .build();

            PurekitProtos.VerifyPasswordResponse response = httpClient.verifyPassword(request);

            byte[] phek = client.checkResponseAndDecrypt(passwordHash,
                    userRecord.getPheRecord(),
                    response.getResponse().toByteArray());

            if (phek.length == 0) {
                throw new PureLogicException(PureLogicException.ErrorStatus.INVALID_PASSWORD);
            }

            return phek;
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] performRotation(byte[] enrollmentRecord) throws PureCryptoException {
        ValidationUtils.checkNull(updateToken, "pheUpdateToken");

        try {
            return previousClient.updateEnrollmentRecord(enrollmentRecord, updateToken);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    PheClientEnrollAccountResult getEnrollment(byte[] passwordHash) throws PureException {
        PurekitProtos.EnrollmentRequest request = PurekitProtos.EnrollmentRequest
                .newBuilder()
                .setVersion(currentVersion)
                .build();

        PurekitProtos.EnrollmentResponse response = httpClient.enrollAccount(request);

        try {
            return currentClient.enrollAccount(
                    response.getResponse().toByteArray(),
                    passwordHash
            );
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }
}
