package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.virgilsecurity.crypto.phe.PheClient;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
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

    public PheManager(PureContext context) {
        this.crypto = context.getCrypto();

        this.currentClient = new PheClient();
        this.currentClient.setOperationRandom(this.crypto.getRng());
        this.currentClient.setRandom(this.crypto.getRng());
        this.currentClient.setKeys(context.getSecretKey().getPayload1(),
                context.getPublicKey().getPayload1());

        if (context.getUpdateToken() != null) {
            this.currentVersion = context.getPublicKey().getVersion() + 1;
            this.updateToken = context.getUpdateToken().getPayload1();
            this.previousClient = new PheClient();
            this.previousClient.setOperationRandom(this.crypto.getRng());
            this.previousClient.setRandom(this.crypto.getRng());
            this.previousClient.setKeys(context.getSecretKey().getPayload1(),
                    context.getPublicKey().getPayload1());
            this.currentClient.rotateKeys(context.getUpdateToken().getPayload1());
        } else {
            this.currentVersion = context.getPublicKey().getVersion();
            this.updateToken = null;
            this.previousClient = null;
        }

        this.httpClient = context.getPheClient();
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

    byte[] computePheKey(UserRecord userRecord, String password) throws Exception {
        byte[] passwordHash = crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

        return computePheKey(userRecord, passwordHash);
    }

    byte[] computePheKey(UserRecord userRecord, byte[] passwordHash) throws Exception {

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

    byte[] performRotation(byte[] enrollmentRecord) {
        ValidateUtils.checkNull(updateToken, "pheUpdateToken");

        return previousClient.updateEnrollmentRecord(enrollmentRecord, updateToken);
    }

    PheClientEnrollAccountResult getEnrollment(byte[] passwordHash) throws ProtocolHttpException, ProtocolException {
        PurekitProtos.EnrollmentRequest request = PurekitProtos.EnrollmentRequest
                .newBuilder()
                .setVersion(currentVersion)
                .build();

        PurekitProtos.EnrollmentResponse response = httpClient.enrollAccount(request);
        return currentClient.enrollAccount(
                response.getResponse().toByteArray(),
                passwordHash
        );
    }
}
