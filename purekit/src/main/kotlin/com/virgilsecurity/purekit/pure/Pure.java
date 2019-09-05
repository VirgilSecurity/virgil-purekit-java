package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.sun.tools.javac.util.StringUtils;
import com.virgilsecurity.crypto.foundation.Aes256Gcm;
import com.virgilsecurity.crypto.foundation.AuthEncryptAuthEncryptResult;
import com.virgilsecurity.crypto.foundation.Hkdf;
import com.virgilsecurity.crypto.foundation.Sha512;
import com.virgilsecurity.crypto.phe.PheCipher;
import com.virgilsecurity.crypto.phe.PheClient;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3;
import com.virgilsecurity.sdk.crypto.KeyType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class Pure {
    private PureStorage storage;
    private byte[] authKey;
    private HttpPheClient client;
    private int currentVersion;
    private byte[] updateToken;
    private PheClient currentClient;
    private PheClient previousClient;
    private VirgilCrypto crypto;
    private PheCipher cipher;

    public Pure(String authToken, byte[] authKey, PureStorage storage, int currentVersion, String updateToken) {
        this.storage = storage;
        this.authKey = authKey;
        this.client = new HttpPheClient(authToken);
        this.currentVersion = currentVersion;
        this.crypto = new VirgilCrypto();

        if (updateToken != null) {
            this.updateToken = Pure.parseUpdateToken(updateToken, currentVersion);
            this.previousClient = new PheClient();
            this.previousClient.setupDefaults();
            // TODO:
//            this.previousClient.setKeys();
        }

        this.currentClient = new PheClient();
        this.currentClient.setupDefaults();
        // TODO:
//        this.currentClient.setKeys();

        this.cipher = new PheCipher();
        this.cipher.setRandom(this.crypto.getRng());
    }

    private void registerUser(String userId, String password, boolean isUserNew) throws ProtocolException, ProtocolHttpException, CryptoException {
        if (userId == null || userId.isEmpty()) {
            throw new NullPointerException();
        }
        if (password == null || password.isEmpty()) {
            throw new NullPointerException();
        }

        PurekitProtos.EnrollmentRequest request = PurekitProtos.EnrollmentRequest.newBuilder().setVersion(this.currentVersion).build();
        PurekitProtos.EnrollmentResponse response = this.client.enrollAccount(request);

        PheClientEnrollAccountResult result = this.currentClient.enrollAccount(response.toByteArray(), password.getBytes());

        byte[] pheRecord = PurekitProtos.DatabaseRecord.newBuilder()
                .setVersion(this.currentVersion)
                .setRecord(ByteString.copyFrom(result.getEnrollmentRecord()))
                .build()
                .toByteArray();

        // TODO: Encrypt hashed password for backup?
        // FIXME: Do we need asymmetric crypto here?
        VirgilKeyPair pheKeyPair = this.crypto.generateKeyPair(KeyType.ED25519, result.getAccountKey());

        VirgilKeyPair userKeyPair = this.crypto.generateKeyPair();

        byte[] privateKeyData = this.crypto.exportPrivateKey(userKeyPair.getPrivateKey());

        // TODO: Add backup key to this list
        // TODO: Do we need signature here?
        byte[] encryptedUsk = this.crypto.encrypt(privateKeyData, Arrays.asList(pheKeyPair.getPublicKey()));

        UserRecord userRecord = new UserRecord();
        userRecord.setUserId(userId);
        userRecord.setPheRecord(pheRecord);
        userRecord.setPheRecordVersion(this.currentVersion);
        userRecord.setUpk(this.crypto.exportPublicKey(userKeyPair.getPublicKey()));
        userRecord.setEncryptedUsk(encryptedUsk);

        if (isUserNew) {
            this.storage.insertUser(userRecord);
        }
        else {
            this.storage.updateUser(userRecord);
        }
    }

    public void registerUser(String userId, String password) throws ProtocolException, ProtocolHttpException, CryptoException {
        this.registerUser(userId, password, true);
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
        if (userId == null || userId.isEmpty()) {
            throw new NullPointerException();
        }
        if (password == null || password.isEmpty()) {
            throw new NullPointerException();
        }

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

        if (sessionId != null) {
            grant.setSessionId(sessionId);
        }

        return grant;
    }

    public PureGrant authenticateUser(String userId, String password) throws Exception, ProtocolHttpException, ProtocolException {
        return this.authenticateUser(userId, password, null);
    }

    public String encryptGrantForUser(PureGrant grant) {
        if (grant == null) {
            throw new NullPointerException();
        }

        int timestamp = (int) (grant.getCreationDate().getTime() / 1000);
        PurekitProtosV3.EncryptedGrantHeader header = PurekitProtosV3.EncryptedGrantHeader.newBuilder()
                .setCreationDate(timestamp)
                .setUserId(grant.getUserId())
                .setSessionId(grant.getSessionId())
                .build();

        byte[] headerBytes = header.toByteArray();

        // TODO: Add headerBytes as auth data
        byte[] result = this.cipher.encrypt(grant.getPhek(), this.authKey);

        PurekitProtosV3.EncryptedGrant encryptedGrant = PurekitProtosV3.EncryptedGrant.newBuilder()
                .setVersion(1)
                .setHeader(ByteString.copyFrom(headerBytes))
                .setEncryptedPhek(ByteString.copyFrom(result))
                .build();

        return Base64.getEncoder().encodeToString(encryptedGrant.toByteArray());
    }

    public PureGrant decryptGrantFromUser(String encryptedGrantString) throws InvalidProtocolBufferException  {
        if (encryptedGrantString == null || encryptedGrantString.isEmpty()) {
            throw new NullPointerException();
        }

        byte[] encryptedGrantData = Base64.getDecoder().decode(encryptedGrantString);

        PurekitProtosV3.EncryptedGrant encryptedGrant = PurekitProtosV3.EncryptedGrant.parseFrom(encryptedGrantData);

        ByteString encryptedData = encryptedGrant.getEncryptedPhek();

        // TODO: Add encryptedGrant.getHeader().toByteArray() as auth data
        byte[] key = this.cipher.decrypt(encryptedData.toByteArray(), this.authKey);

        PurekitProtosV3.EncryptedGrantHeader header = PurekitProtosV3.EncryptedGrantHeader.parseFrom(encryptedGrant.getHeader());

        PureGrant grant = new PureGrant();

        grant.setSessionId(header.getSessionId());
        grant.setUserId(header.getUserId());
        grant.setCreationDate(new Date((long)header.getCreationDate() * 1000));
        grant.setPhek(key);

        return grant;
    }

    public void changeUserPassword(String userId, String oldPassword, String newPassword) throws ProtocolException, ProtocolHttpException, CryptoException, Exception {
        if (userId == null || userId.isEmpty()) {
            throw new NullPointerException();
        }
        if (oldPassword == null || oldPassword.isEmpty()) {
            throw new NullPointerException();
        }
        if (newPassword == null || newPassword.isEmpty()) {
            throw new NullPointerException();
        }

        UserRecord userRecord = this.storage.selectUser(userId);

        PheClient client = this.getClient(userRecord.getPheRecordVersion());

        byte[] pheVerifyRequest = client.createVerifyPasswordRequest(oldPassword.getBytes(), userRecord.getPheRecord());

        PurekitProtos.VerifyPasswordRequest verifyRequest = PurekitProtos.VerifyPasswordRequest.newBuilder()
                .setVersion(userRecord.getPheRecordVersion())
                .setRequest(ByteString.copyFrom(pheVerifyRequest))
                .build();

        PurekitProtos.VerifyPasswordResponse verifyResponse = this.client.verifyPassword(verifyRequest);

        byte[] key = client.checkResponseAndDecrypt(oldPassword.getBytes(), userRecord.getPheRecord(), verifyResponse.getResponse().toByteArray());

        // TODO: Encrypt hashed password for backup?
        // FIXME: Do we need asymmetric crypto here?
        VirgilKeyPair oldPheKeyPair = this.crypto.generateKeyPair(KeyType.ED25519, key);

        PurekitProtos.EnrollmentRequest enrollRequest = PurekitProtos.EnrollmentRequest.newBuilder().setVersion(this.currentVersion).build();
        PurekitProtos.EnrollmentResponse enrollResponse = this.client.enrollAccount(enrollRequest);

        PheClientEnrollAccountResult enrollResult = this.currentClient.enrollAccount(enrollResponse.toByteArray(), newPassword.getBytes());

        byte[] pheRecord = PurekitProtos.DatabaseRecord.newBuilder()
                .setVersion(this.currentVersion)
                .setRecord(ByteString.copyFrom(enrollResult.getEnrollmentRecord()))
                .build()
                .toByteArray();

        userRecord.setPheRecord(pheRecord);
        userRecord.setPheRecordVersion(this.currentVersion);

        // TODO: Encrypt hashed password for backup?
        // FIXME: Do we need asymmetric crypto here?
        VirgilKeyPair newPheKeyPair = this.crypto.generateKeyPair(KeyType.ED25519, enrollResult.getAccountKey());

        // TODO: Do we need signature here?
        byte[] privateKeyData = this.crypto.decrypt(userRecord.getEncryptedUsk(), oldPheKeyPair.getPrivateKey());

        // TODO: Add backup key to this list
        // TODO: Do we need signature here?
        byte[] newEncryptedUsk = this.crypto.encrypt(privateKeyData, Arrays.asList(newPheKeyPair.getPublicKey()));

        userRecord.setEncryptedUsk(newEncryptedUsk);

        this.storage.updateUser(userRecord);
    }

    public void resetUserPassword(String userId, String newPassword) throws ProtocolException, ProtocolHttpException, CryptoException {
        this.registerUser(userId, newPassword, false);
    }

    private static byte[] parseUpdateToken(String updateToken, int currentVersion) {
        if (updateToken == null) {
            return null;
        }

        String[] parts = updateToken.split(".");

        if (parts.length != 3) {
            throw new NullPointerException();
        }

        if (!parts[0].equals("UT")) {
            throw new NullPointerException();
        }

        int version = Integer.parseInt(parts[1]);

        if (version != currentVersion) {
            throw new NullPointerException();
        }

        return Base64.getDecoder().decode(parts[2]);
    }

    public long performRotation() throws Exception {
        if (this.updateToken == null) {
            throw new NullPointerException();
        }

        if (this.currentVersion <= 1) {
            return 0;
        }

        long rotated = 0;

        PheClient pheClient = this.getClient(this.currentVersion - 1);

        while (true) {
            UserRecord[] userRecords = this.storage.selectUsers(this.currentVersion - 1);

            if (userRecords.length == 0) {
                break;
            }

            for (UserRecord userRecord: userRecords) {
                assert userRecord.getPheRecordVersion() == this.currentVersion - 1;

                byte[] newRecord = pheClient.updateEnrollmentRecord(userRecord.getPheRecord(), this.updateToken);

                userRecord.setPheRecordVersion(this.currentVersion);
                userRecord.setPheRecord(newRecord);

                this.storage.updateUser(userRecord);

                rotated += 1;
            }
        }

        return rotated;
    }
}
