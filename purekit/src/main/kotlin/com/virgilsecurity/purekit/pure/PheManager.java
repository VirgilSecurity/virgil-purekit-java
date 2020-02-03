package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.phe.PheClient;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
import com.virgilsecurity.crypto.phe.PheClientRotateKeysResult;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.UserRecord;
import com.virgilsecurity.purekit.utils.ValidateUtils;
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

    byte[] computePheKey(UserRecord userRecord, String password) throws ProtocolException, PureLogicException, PureCryptoException, ProtocolHttpException {
        byte[] passwordHash = crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

        return computePheKey(userRecord, passwordHash);
    }

    byte[] computePheKey(UserRecord userRecord, byte[] passwordHash) throws PureLogicException, PureCryptoException, ProtocolHttpException, ProtocolException {

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
        ValidateUtils.checkNull(updateToken, "pheUpdateToken");

        try {
            return previousClient.updateEnrollmentRecord(enrollmentRecord, updateToken);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    PheClientEnrollAccountResult getEnrollment(byte[] passwordHash) throws ProtocolHttpException, ProtocolException, PureCryptoException {
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
