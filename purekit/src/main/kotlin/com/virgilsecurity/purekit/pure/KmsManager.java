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

package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.crypto.phe.UokmsClient;
import com.virgilsecurity.crypto.phe.UokmsClientGenerateDecryptRequestResult;
import com.virgilsecurity.crypto.phe.UokmsClientGenerateEncryptWrapResult;
import com.virgilsecurity.crypto.phe.UokmsClientRotateKeysResult;
import com.virgilsecurity.crypto.phe.UokmsWrapRotation;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Client;
import com.virgilsecurity.purekit.pure.client.HttpKmsClient;
import com.virgilsecurity.purekit.pure.exception.KmsClientException;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.model.GrantKey;
import com.virgilsecurity.purekit.pure.model.UserRecord;
import com.virgilsecurity.purekit.utils.ValidateUtils;

class KmsManager {
    public static final String RECOVER_PWD_ALIAS = "RECOVERY_PASSWORD";

    private final int currentVersion;
    private final PureCrypto pureCrypto;
    private final UokmsClient pwdCurrentClient;
    private final UokmsClient pwdPreviousClient;
    private final UokmsClient grantCurrentClient;
    private final UokmsClient grantPreviousClient;
    private final HttpKmsClient httpClient;
    private final UokmsWrapRotation pwdKmsRotation;
    private final UokmsWrapRotation grantKmsRotation;

    public KmsManager(PureContext context) throws PureCryptoException {
        try {
            this.pureCrypto = new PureCrypto(context.getCrypto());
            this.pwdCurrentClient = new UokmsClient();
            this.pwdCurrentClient.setOperationRandom(context.getCrypto().getRng());
            this.pwdCurrentClient.setRandom(context.getCrypto().getRng());
            this.grantCurrentClient = new UokmsClient();
            this.grantCurrentClient.setOperationRandom(context.getCrypto().getRng());
            this.grantCurrentClient.setRandom(context.getCrypto().getRng());

            if (context.getUpdateToken() != null) {
                this.currentVersion = context.getPublicKey().getVersion() + 1;

                byte[] pwdUpdateToken = context.getUpdateToken().getPayload2();
                this.pwdKmsRotation = new UokmsWrapRotation();
                this.pwdKmsRotation.setOperationRandom(context.getCrypto().getRng());
                this.pwdKmsRotation.setUpdateToken(pwdUpdateToken);
                this.pwdPreviousClient = new UokmsClient();
                this.pwdPreviousClient.setOperationRandom(context.getCrypto().getRng());
                this.pwdPreviousClient.setRandom(context.getCrypto().getRng());
                this.pwdPreviousClient.setKeys(context.getSecretKey().getPayload2(),
                        context.getPublicKey().getPayload2());

                byte[] grantUpdateToken = context.getUpdateToken().getPayload3();
                this.grantKmsRotation = new UokmsWrapRotation();
                this.grantKmsRotation.setOperationRandom(context.getCrypto().getRng());
                this.grantKmsRotation.setUpdateToken(grantUpdateToken);
                this.grantPreviousClient = new UokmsClient();
                this.grantPreviousClient.setOperationRandom(context.getCrypto().getRng());
                this.grantPreviousClient.setRandom(context.getCrypto().getRng());
                this.grantPreviousClient.setKeysOneparty(context.getSecretKey().getPayload3());

                UokmsClientRotateKeysResult rotateKeysResult = this.pwdPreviousClient.rotateKeys(pwdUpdateToken);
                this.pwdCurrentClient.setKeys(rotateKeysResult.getNewClientPrivateKey(), rotateKeysResult.getNewServerPublicKey());

                byte[] newGrantPrivateKey = this.grantPreviousClient.rotateKeysOneparty(grantUpdateToken);
                this.grantCurrentClient.setKeysOneparty(newGrantPrivateKey);
            } else {
                this.currentVersion = context.getPublicKey().getVersion();
                this.pwdKmsRotation = null;
                this.pwdPreviousClient = null;
                this.grantKmsRotation = null;
                this.grantPreviousClient = null;
                this.pwdCurrentClient.setKeys(context.getSecretKey().getPayload2(),
                        context.getPublicKey().getPayload2());
                this.grantCurrentClient.setKeysOneparty(context.getSecretKey().getPayload3());
            }

            this.httpClient = context.getKmsClient();
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    private UokmsClient getPwdClient(int kmsVersion) throws NullPointerException {
        if (this.currentVersion == kmsVersion) {
            return this.pwdCurrentClient;
        } else if (this.currentVersion == kmsVersion + 1) {
            return this.pwdPreviousClient;
        } else {
            throw new NullPointerException("kmsClient");
        }
    }

    private UokmsClient getGrantClient(int kmsVersion) throws NullPointerException {
        if (this.currentVersion == kmsVersion) {
            return this.grantCurrentClient;
        } else if (this.currentVersion == kmsVersion + 1) {
            return this.grantPreviousClient;
        } else {
            throw new NullPointerException("kmsClient");
        }
    }

    private byte[] recoverPwdSecret(UserRecord userRecord) throws PureException {
        try {
            UokmsClient kmsClient = getPwdClient(userRecord.getRecordVersion());

            UokmsClientGenerateDecryptRequestResult uokmsClientGenerateDecryptRequestResult = kmsClient.generateDecryptRequest(userRecord.getPasswordRecoveryWrap());

            PurekitProtosV3Client.DecryptRequest decryptRequest = PurekitProtosV3Client.DecryptRequest.newBuilder()
                    .setVersion(userRecord.getRecordVersion())
                    .setAlias(RECOVER_PWD_ALIAS)
                    .setRequest(ByteString.copyFrom(uokmsClientGenerateDecryptRequestResult.getDecryptRequest()))
                    .build();

            PurekitProtosV3Client.DecryptResponse decryptResponse = httpClient.decrypt(decryptRequest);

            return kmsClient.processDecryptResponse(userRecord.getPasswordRecoveryWrap(),
                    uokmsClientGenerateDecryptRequestResult.getDecryptRequest(),
                    decryptResponse.getResponse().toByteArray(),
                    uokmsClientGenerateDecryptRequestResult.getDeblindFactor(),
                    PureCrypto.DERIVED_SECRET_LENGTH);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        } catch (ProtocolException e) {
            throw new KmsClientException(e);
        } catch (ProtocolHttpException e) {
            throw new KmsClientException(e);
        }
    }

    private byte[] recoverGrantKeySecret(GrantKey grantKey) throws PureException {
        try {
            UokmsClient kmsClient = getGrantClient(grantKey.getRecordVersion());

            return kmsClient.decryptOneparty(grantKey.getEncryptedGrantKeyWrap(), PureCrypto.DERIVED_SECRET_LENGTH);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] performPwdRotation(byte[] wrap) throws PureCryptoException {
        try {
            ValidateUtils.checkNull(pwdKmsRotation, "kmsUpdateToken");
            ValidateUtils.checkNull(wrap, "wrap");

            return pwdKmsRotation.updateWrap(wrap);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] performGrantRotation(byte[] wrap) throws PureCryptoException {
        try {
            ValidateUtils.checkNull(grantKmsRotation, "grantUpdateToken");
            ValidateUtils.checkNull(wrap, "wrap");

            return grantKmsRotation.updateWrap(wrap);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    static class KmsEncryptedData {
        private final byte[] wrap;
        private final byte[] blob;

        public KmsEncryptedData(byte[] wrap, byte[] blob) {
            ValidateUtils.checkNull(wrap, "wrap");
            ValidateUtils.checkNull(blob, "blob");

            this.wrap = wrap;
            this.blob = blob;
        }

        public byte[] getWrap() {
            return wrap;
        }

        public byte[] getBlob() {
            return blob;
        }
    }

    byte[] recoverPwd(UserRecord userRecord) throws PureException {
        byte[] derivedSecret = recoverPwdSecret(userRecord);

        return pureCrypto.decryptSymmetricWithOneTimeKey(userRecord.getPasswordRecoveryBlob(), new byte[0], derivedSecret);
    }

    byte[] recoverGrantKey(GrantKey grantKey, byte[] header) throws PureException {
        byte[] derivedSecret = recoverGrantKeySecret(grantKey);

        return pureCrypto.decryptSymmetricWithOneTimeKey(grantKey.getEncryptedGrantKeyBlob(), header, derivedSecret);
    }

    KmsEncryptedData generatePwdRecoveryData(byte[] passwordHash) throws PureCryptoException {
        return generateEncryptionData(passwordHash, new byte[0], true);
    }

    KmsEncryptedData generateGrantKeyEncryptionData(byte[] grantKey, byte[] header) throws PureCryptoException {
        return generateEncryptionData(grantKey, header, false);
    }

    private KmsEncryptedData generateEncryptionData(byte[] data, byte[] header, boolean isPwd) throws PureCryptoException {
        try {
            UokmsClientGenerateEncryptWrapResult kmsResult = (isPwd ? pwdCurrentClient : grantCurrentClient)
                    .generateEncryptWrap(PureCrypto.DERIVED_SECRET_LENGTH);

            byte[] derivedSecret = kmsResult.getEncryptionKey();

            byte[] resetPwdBlob = pureCrypto.encryptSymmetricWithOneTimeKey(data, header, derivedSecret);

            return new KmsEncryptedData(kmsResult.getWrap(), resetPwdBlob);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }
}
