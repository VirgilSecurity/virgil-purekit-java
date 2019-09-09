package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.virgilsecurity.crypto.phe.PheCipher;
import com.virgilsecurity.crypto.phe.PheClient;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class Pure {
    private VirgilCrypto crypto;
    private PureCrypto pureCrypto;
    private PheCipher cipher;
    private PureStorage storage;
    private int currentVersion;
    private PheClient currentClient;
    private byte[] updateToken;
    private PheClient previousClient;
    private byte[] ak;
    private VirgilPublicKey buppk;
    private VirgilPublicKey hpk;
    private HttpPheClient client;

    public Pure(PureContext context) throws CryptoException {
        this.crypto = new VirgilCrypto();
        this.pureCrypto = new PureCrypto(this.crypto);
        this.cipher = new PheCipher();
        this.cipher.setRandom(this.crypto.getRng());
        this.storage = context.getStorage();
        this.currentClient = new PheClient();
        this.currentClient.setOperationRandom(this.crypto.getRng());
        this.currentClient.setRandom(this.crypto.getRng());

        ParseResult skResult = Pure.parseCredentials("SK", context.getAppSecretKey());
        ParseResult pkResult = Pure.parseCredentials("PK", context.getServicePublicKey());

        if (skResult.getVersion() != pkResult.getVersion()) {
            throw new NullPointerException();
        }

        this.currentVersion = skResult.getVersion();
        this.currentClient.setKeys(skResult.getPayload(), pkResult.getPayload());

        if (context.getUpdateToken() != null) {
            ParseResult utResult = Pure.parseCredentials("UT", context.getUpdateToken());

            if (utResult.getVersion() != this.currentVersion + 1) {
                throw new NullPointerException();
            }

            this.currentVersion += 1;
            this.updateToken = utResult.getPayload();
            this.previousClient = new PheClient();
            this.previousClient.setOperationRandom(this.crypto.getRng());
            this.previousClient.setRandom(this.crypto.getRng());
            this.previousClient.setKeys(skResult.getPayload(), pkResult.getPayload());
            this.currentClient.rotateKeys(utResult.getPayload());
        }

        // TODO: Check size
        this.ak = context.getAk();
        this.buppk = this.crypto.importPublicKey(context.getBuppk());
        this.hpk = this.crypto.importPublicKey(context.getHpk());
        this.client = new HttpPheClient(context.getAuthToken(), context.getServiceAddress());
    }

    private static class ParseResult {
        private byte[] payload;
        private int version;

        private byte[] getPayload() {
            return payload;
        }

        private int getVersion() {
            return version;
        }

        private ParseResult(byte[] payload, int version) {
            this.payload = payload;
            this.version = version;
        }
    }

    private static ParseResult parseCredentials(String prefix, String credentials) {
        if (prefix == null || prefix.isEmpty()) {
            throw new NullPointerException();
        }
        if (credentials == null || credentials.isEmpty()) {
            throw new NullPointerException();
        }

        String[] parts = credentials.split("\\.");

        if (parts.length != 3) {
            throw new NullPointerException();
        }

        if (!parts[0].equals(prefix)) {
            throw new NullPointerException();
        }

        int version = Integer.parseInt(parts[1]);
        byte[] payload = Base64.getDecoder().decode(parts[2]);;

        return new ParseResult(payload, version);
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

        byte[] passwordHash = this.crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

        byte[] encryptedPwdHash = this.crypto.encrypt(passwordHash, Arrays.asList(this.hpk));

        PheClientEnrollAccountResult result = this.currentClient.enrollAccount(response.getResponse().toByteArray(), passwordHash);

        VirgilKeyPair phekp = this.crypto.generateKeyPair(result.getAccountKey());

        VirgilKeyPair ukp = this.crypto.generateKeyPair();

        byte[] uskData = this.crypto.exportPrivateKey(ukp.getPrivateKey());

        // TODO: Do we need signature here?
        byte[] encryptedUsk = this.crypto.encrypt(uskData, Arrays.asList(phekp.getPublicKey(), this.buppk));

        UserRecord userRecord = new UserRecord();
        userRecord.setUserId(userId);
        userRecord.setPheRecord(result.getEnrollmentRecord());
        userRecord.setPheRecordVersion(this.currentVersion);
        userRecord.setUpk(this.crypto.exportPublicKey(ukp.getPublicKey()));
        userRecord.setEncryptedUsk(encryptedUsk);
        userRecord.setEncryptedPwdHash(encryptedPwdHash);

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

    private PheClient getClient(int pheVersion) throws NullPointerException {
        if (this.currentVersion == pheVersion) {
            return this.currentClient;
        }
        else if (this.currentVersion == pheVersion + 1) {
            return this.previousClient;
        }
        else {
            throw new NullPointerException();
        }
    }

    public AuthResult authenticateUser(String userId, String password, String sessionId) throws ProtocolHttpException, ProtocolException, CryptoException {
        if (userId == null || userId.isEmpty()) {
            throw new NullPointerException();
        }
        if (password == null || password.isEmpty()) {
            throw new NullPointerException();
        }

        byte[] passwordHash = this.crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

        UserRecord userRecord = this.storage.selectUser(userId);

        PheClient client = this.getClient(userRecord.getPheRecordVersion());

        byte[] pheVerifyRequest = client.createVerifyPasswordRequest(passwordHash, userRecord.getPheRecord());

        PurekitProtos.VerifyPasswordRequest request = PurekitProtos.VerifyPasswordRequest.newBuilder()
                .setVersion(userRecord.getPheRecordVersion())
                .setRequest(ByteString.copyFrom(pheVerifyRequest))
                .build();

        PurekitProtos.VerifyPasswordResponse response = this.client.verifyPassword(request);

        byte[] phesd = client.checkResponseAndDecrypt(passwordHash, userRecord.getPheRecord(), response.getResponse().toByteArray());

        VirgilKeyPair phekp = this.crypto.generateKeyPair(phesd);

        byte[] usk = this.crypto.decrypt(userRecord.getEncryptedUsk(), phekp.getPrivateKey());

        VirgilKeyPair ukp = this.crypto.importPrivateKey(usk);

        PureGrant grant = new PureGrant(ukp, userId, sessionId, new Date());

        int timestamp = (int) (grant.getCreationDate().getTime() / 1000);
        PurekitProtosV3.EncryptedGrantHeader.Builder headerBuilder = PurekitProtosV3.EncryptedGrantHeader.newBuilder()
                .setCreationDate(timestamp)
                .setUserId(grant.getUserId());

        if (sessionId != null) {
            headerBuilder.setSessionId(sessionId);
        }

        PurekitProtosV3.EncryptedGrantHeader header = headerBuilder.build();

        byte[] headerBytes = header.toByteArray();

        byte[] phesk = this.crypto.exportPrivateKey(phekp.getPrivateKey());

        byte[] encryptedPhesk = this.cipher.authEncrypt(phesk, headerBytes, this.ak);

        PurekitProtosV3.EncryptedGrant encryptedGrantData = PurekitProtosV3.EncryptedGrant.newBuilder()
                .setVersion(1) /* FIXME */
                .setHeader(ByteString.copyFrom(headerBytes))
                .setEncryptedPhesk(ByteString.copyFrom(encryptedPhesk))
                .build();

        String encryptedGrant = Base64.getEncoder().encodeToString(encryptedGrantData.toByteArray());

        return new AuthResult(grant, encryptedGrant);
    }

    public AuthResult authenticateUser(String userId, String password) throws Exception, ProtocolHttpException, ProtocolException {
        return this.authenticateUser(userId, password, null);
    }

    public PureGrant createAdminGrant(String userId, VirgilPrivateKey bupsk) throws CryptoException {
        UserRecord userRecord = this.storage.selectUser(userId);

        byte[] usk = this.crypto.decrypt(userRecord.getEncryptedUsk(), bupsk);

        VirgilKeyPair upk = this.crypto.importPrivateKey(usk);

        return new PureGrant(upk, userId, null, new Date());
    }

    public PureGrant decryptGrantFromUser(String encryptedGrantString) throws InvalidProtocolBufferException, CryptoException {
        if (encryptedGrantString == null || encryptedGrantString.isEmpty()) {
            throw new NullPointerException();
        }

        byte[] encryptedGrantData = Base64.getDecoder().decode(encryptedGrantString);

        PurekitProtosV3.EncryptedGrant encryptedGrant = PurekitProtosV3.EncryptedGrant.parseFrom(encryptedGrantData);

        ByteString encryptedData = encryptedGrant.getEncryptedPhesk();

        byte[] phesk = this.cipher.authDecrypt(encryptedData.toByteArray(), encryptedGrant.getHeader().toByteArray(), this.ak);

        VirgilKeyPair phekp = this.crypto.importPrivateKey(phesk);

        PurekitProtosV3.EncryptedGrantHeader header = PurekitProtosV3.EncryptedGrantHeader.parseFrom(encryptedGrant.getHeader());

        UserRecord userRecord = this.storage.selectUser(header.getUserId());

        byte[] usk = this.crypto.decrypt(userRecord.getEncryptedUsk(), phekp.getPrivateKey());

        VirgilKeyPair ukp = this.crypto.importPrivateKey(usk);

        return new PureGrant(ukp, header.getUserId(), header.getSessionId(), new Date((long)header.getCreationDate() * 1000));
    }

    public void changeUserPassword(String userId, String oldPassword, String newPassword) throws ProtocolException, ProtocolHttpException, CryptoException {
        if (userId == null || userId.isEmpty()) {
            throw new NullPointerException();
        }
        if (oldPassword == null || oldPassword.isEmpty()) {
            throw new NullPointerException();
        }
        if (newPassword == null || newPassword.isEmpty()) {
            throw new NullPointerException();
        }

        byte[] oldPasswordHash = this.crypto.computeHash(oldPassword.getBytes(), HashAlgorithm.SHA512);
        byte[] newPasswordHash = this.crypto.computeHash(newPassword.getBytes(), HashAlgorithm.SHA512);

        UserRecord userRecord = this.storage.selectUser(userId);

        PheClient client = this.getClient(userRecord.getPheRecordVersion());

        byte[] pheVerifyRequest = client.createVerifyPasswordRequest(oldPasswordHash, userRecord.getPheRecord());

        PurekitProtos.VerifyPasswordRequest verifyRequest = PurekitProtos.VerifyPasswordRequest.newBuilder()
                .setVersion(userRecord.getPheRecordVersion())
                .setRequest(ByteString.copyFrom(pheVerifyRequest))
                .build();

        PurekitProtos.VerifyPasswordResponse verifyResponse = this.client.verifyPassword(verifyRequest);

        byte[] oldPhek = client.checkResponseAndDecrypt(oldPasswordHash, userRecord.getPheRecord(), verifyResponse.getResponse().toByteArray());

        VirgilKeyPair oldPhekp = this.crypto.generateKeyPair(oldPhek);

        PurekitProtos.EnrollmentRequest enrollRequest = PurekitProtos.EnrollmentRequest.newBuilder().setVersion(this.currentVersion).build();
        PurekitProtos.EnrollmentResponse enrollResponse = this.client.enrollAccount(enrollRequest);

        PheClientEnrollAccountResult enrollResult = this.currentClient.enrollAccount(enrollResponse.toByteArray(), newPasswordHash);

        byte[] pheRecord = PurekitProtos.DatabaseRecord.newBuilder()
                .setVersion(this.currentVersion)
                .setRecord(ByteString.copyFrom(enrollResult.getEnrollmentRecord()))
                .build()
                .toByteArray();

        userRecord.setPheRecord(pheRecord);
        userRecord.setPheRecordVersion(this.currentVersion);

        VirgilKeyPair newPhekp = this.crypto.generateKeyPair(enrollResult.getAccountKey());

        // TODO: Do we need signature here?
        byte[] privateKeyData = this.crypto.decrypt(userRecord.getEncryptedUsk(), oldPhekp.getPrivateKey());

        // TODO: Do we need signature here?
        byte[] newEncryptedUsk = this.crypto.encrypt(privateKeyData, Arrays.asList(newPhekp.getPublicKey(), this.buppk));

        userRecord.setEncryptedUsk(newEncryptedUsk);

        byte[] encryptedPwdHash = this.crypto.encrypt(newPasswordHash, Arrays.asList(this.hpk));
        userRecord.setEncryptedPwdHash(encryptedPwdHash);

        this.storage.updateUser(userRecord);
    }

    public void resetUserPassword(String userId, String newPassword) throws ProtocolException, ProtocolHttpException, CryptoException {
        this.registerUser(userId, newPassword, false);
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

    public byte[] encrypt(String userId, String dataId, byte[] plainText) throws CryptoException {
        if (userId == null || userId.isEmpty()) {
            throw new NullPointerException();
        }
        if (dataId == null || dataId.isEmpty()) {
            throw new NullPointerException();
        }

        VirgilPublicKey cpk;

        // Try to generate and save new key
        try {
            UserRecord userRecord = this.storage.selectUser(userId);

            VirgilPublicKey upk = this.crypto.importPublicKey(userRecord.getUpk());

            VirgilKeyPair ckp = this.crypto.generateKeyPair();

            byte[] cpkData = this.crypto.exportPublicKey(ckp.getPublicKey());
            byte[] cskData = this.crypto.exportPrivateKey(ckp.getPrivateKey());

            // TODO: Do we need signature here?
            PureCryptoData encryptedCskData = this.pureCrypto.encrypt(cskData, Arrays.asList(upk));
            this.storage.insertKey(userId, dataId, cpkData, encryptedCskData.getCms(), encryptedCskData.getBody());
            cpk = ckp.getPublicKey();
        }
        // FIXME: Catch only already exists error
        catch (Exception e) {
            // Key already exists
            CellKey cellKey = this.storage.selectKey(userId, dataId);

            cpk = this.crypto.importPublicKey(cellKey.getCpk());
        }

        // TODO: Add signature?
        return this.crypto.encrypt(plainText, Arrays.asList(cpk));
    }

    public byte[] decrypt(PureGrant grant, String ownerUserId, String dataId, byte[] cipherText) throws CryptoException {
        if (grant == null) {
            throw new NullPointerException();
        }
        if (dataId == null || dataId.isEmpty()) {
            throw new NullPointerException();
        }

        String userId = ownerUserId;

        if (userId == null) {
            userId = grant.getUserId();
        }

        CellKey cellKey = this.storage.selectKey(userId, dataId);

        byte[] csk = this.pureCrypto.decrypt(new PureCryptoData(cellKey.getEncryptedCskCms(), cellKey.getEncryptedCskBody()), grant.getUkp().getPrivateKey());

        VirgilKeyPair ckp = this.crypto.importPrivateKey(csk);

        // TODO: Add signature?
        return this.crypto.decrypt(cipherText, ckp.getPrivateKey());
    }

    public void share(PureGrant grant, String dataId, String otherUserId) throws CryptoException {
        if (grant == null) {
            throw new NullPointerException();
        }
        if (dataId == null || dataId.isEmpty()) {
            throw new NullPointerException();
        }
        if (otherUserId == null || otherUserId.isEmpty()) {
            throw new NullPointerException();
        }

        CellKey cellKey = this.storage.selectKey(grant.getUserId(), dataId);

        UserRecord otherUserRecord = this.storage.selectUser(otherUserId);
        VirgilPublicKey otherUpk = this.crypto.importPublicKey(otherUserRecord.getUpk());

        byte[] encryptedCskCms = this.pureCrypto.addRecipient(cellKey.getEncryptedCskCms(), grant.getUkp().getPrivateKey(), otherUpk);

        this.storage.updateKey(grant.getUserId(), dataId, encryptedCskCms);
    }

    public void unshare(PureGrant grant, String dataId, String otherUserId) throws CryptoException {
        if (dataId == null || dataId.isEmpty()) {
            throw new NullPointerException();
        }
        if (otherUserId == null || otherUserId.isEmpty()) {
            throw new NullPointerException();
        }

        CellKey cellKey = this.storage.selectKey(grant.getUserId(), dataId);

        UserRecord otherUserRecord = this.storage.selectUser(otherUserId);
        VirgilPublicKey otherUpk = this.crypto.importPublicKey(otherUserRecord.getUpk());

        byte[] encryptedCskCms = this.pureCrypto.deleteRecipient(cellKey.getEncryptedCskCms(), grant.getUkp().getPrivateKey(), otherUpk);

        this.storage.updateKey(grant.getUserId(), dataId, encryptedCskCms);
    }
}
