package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.virgilsecurity.crypto.phe.PheClient;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.sdk.crypto.KeyType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import java.util.Arrays;
import java.util.Date;

public class Pure {
    private PureStorage storage;
    private byte[] authKey;
    private HttpPheClient client;
    private int currentVersion;
    private String updateToken;
    private PheClient currentClient;
    private PheClient previousClient;
    private VirgilCrypto crypto;

    public Pure(String authToken, byte[] authKey, PureStorage storage) {
        this.storage = storage;
        this.authKey = authKey;
        this.client = new HttpPheClient(authToken);
        this.currentClient = new PheClient();
        this.crypto = new VirgilCrypto();
    }

    public void registerUser(String userId, String password) throws ProtocolException, ProtocolHttpException, CryptoException {
        PurekitProtos.EnrollmentRequest request = PurekitProtos.EnrollmentRequest.newBuilder().setVersion(this.currentVersion).build();
        PurekitProtos.EnrollmentResponse response = client.enrollAccount(request);

        PheClientEnrollAccountResult result = this.currentClient.enrollAccount(response.toByteArray(), password.getBytes());

        byte[] pheRecord = PurekitProtos.DatabaseRecord.newBuilder()
                .setVersion(this.currentVersion)
                .setRecord(ByteString.copyFrom(result.getEnrollmentRecord()))
                .build()
                .toByteArray();

        // FIXME: Do we need asymmetric crypto here?
        VirgilKeyPair pheKeyPair = this.crypto.generateKeyPair(KeyType.ED25519, result.getAccountKey());

        VirgilKeyPair userKeyPair = this.crypto.generateKeyPair();

        byte[] privateKeyData = this.crypto.exportPrivateKey(userKeyPair.getPrivateKey());

        // TODO: Add backup key to this list
        byte[] encryptedUsk = this.crypto.encrypt(privateKeyData, Arrays.asList(pheKeyPair.getPublicKey()));

        UserRecord userRecord = new UserRecord();
        userRecord.setUserId(userId);
        userRecord.setPheRecord(pheRecord);
        userRecord.setPheRecordVersion(this.currentVersion);
        userRecord.setUpk(this.crypto.exportPublicKey(userKeyPair.getPublicKey()));
        userRecord.setEncryptedUsk(encryptedUsk);

        this.storage.insertUser(userRecord);
    }

    private PheClient getClient(int pheVersion) throws Exception {
        if (this.currentVersion == pheVersion) {
            return this.currentClient;
        }
        else if (this.currentVersion == pheVersion + 1) {
            return this.previousClient;
        }
        else {
            throw new Exception();
        }
    }

    public PureGrant authenticateUser(String userId, String password, String sessionId) throws Exception, ProtocolHttpException, ProtocolException {
        UserRecord userRecord = this.storage.selectUser(userId);

        PheClient client = this.getClient(userRecord.getPheRecordVersion());

        byte[] pheVerifyRequest = client.createVerifyPasswordRequest(password.getBytes(), userRecord.getPheRecord());

        PurekitProtos.VerifyPasswordRequest request = PurekitProtos.VerifyPasswordRequest.newBuilder()
                .setVersion(userRecord.getPheRecordVersion())
                .setRequest(ByteString.copyFrom(pheVerifyRequest))
                .build();

        PurekitProtos.VerifyPasswordResponse response = this.client.verifyPassword(request);

        byte[] key = client.checkResponseAndDecrypt(password.getBytes(), userRecord.getPheRecord(), response.getResponse().toByteArray());

        PureGrant grant = new PureGrant();

        grant.setPhek(key);
        grant.setCreationDate(new Date());
        grant.setSessionId(sessionId);

        return grant;
    }

    public PureGrant authenticateUser(String userId, String password) throws Exception, ProtocolHttpException, ProtocolException {
        return this.authenticateUser(userId, password, null);
    }

    public String encryptGrantForUser(PureGrant grant) {


        return "";
    }
}
