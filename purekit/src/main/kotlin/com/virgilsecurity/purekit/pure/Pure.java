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
    private PureStorage storage;
    private byte[] ak;
    private VirgilPublicKey buppk;
    private VirgilPublicKey hpk;
    private HttpPheClient client;
    private int currentVersion;
    private byte[] updateToken;
    private PheClient currentClient;
    private PheClient previousClient;
    private VirgilCrypto crypto;
    private PheCipher cipher;

    public Pure(String authToken,
                byte[] ak,
                byte[] buppk,
                byte[] hpk,
                PureStorage storage,
                int currentVersion,
                String updateToken) throws CryptoException {
        this.storage = storage;
        this.crypto = new VirgilCrypto();
        this.ak = ak;
        this.buppk = this.crypto.importPublicKey(buppk);
        this.hpk = this.crypto.importPublicKey(hpk);
        this.client = new HttpPheClient(authToken);
        this.currentVersion = currentVersion;

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

        byte[] passwordHash = this.crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

        byte[] encryptedPwdHash = this.crypto.encrypt(passwordHash, Arrays.asList(this.hpk));

        PheClientEnrollAccountResult result = this.currentClient.enrollAccount(response.toByteArray(), passwordHash);

        byte[] pheRecord = PurekitProtos.DatabaseRecord.newBuilder()
                .setVersion(this.currentVersion)
                .setRecord(ByteString.copyFrom(result.getEnrollmentRecord()))
                .build()
                .toByteArray();

        VirgilKeyPair phekp = this.crypto.generateKeyPair(result.getAccountKey());

        VirgilKeyPair ukp = this.crypto.generateKeyPair();

        byte[] uskData = this.crypto.exportPrivateKey(ukp.getPrivateKey());

        // TODO: Do we need signature here?
        byte[] encryptedUsk = this.crypto.encrypt(uskData, Arrays.asList(phekp.getPublicKey(), this.buppk));

        UserRecord userRecord = new UserRecord();
        userRecord.setUserId(userId);
        userRecord.setPheRecord(pheRecord);
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
        byte[] pheskData = this.crypto.exportPrivateKey(phekp.getPrivateKey());

        PureGrant grant = new PureGrant();

        grant.setPhesk(pheskData);
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
        byte[] result = this.cipher.encrypt(grant.getPhesk(), this.ak);

        PurekitProtosV3.EncryptedGrant encryptedGrant = PurekitProtosV3.EncryptedGrant.newBuilder()
                .setVersion(1) /* FIXME */
                .setHeader(ByteString.copyFrom(headerBytes))
                .setEncryptedPhesk(ByteString.copyFrom(result))
                .build();

        return Base64.getEncoder().encodeToString(encryptedGrant.toByteArray());
    }

    public PureGrant decryptGrantFromUser(String encryptedGrantString) throws InvalidProtocolBufferException  {
        if (encryptedGrantString == null || encryptedGrantString.isEmpty()) {
            throw new NullPointerException();
        }

        byte[] encryptedGrantData = Base64.getDecoder().decode(encryptedGrantString);

        PurekitProtosV3.EncryptedGrant encryptedGrant = PurekitProtosV3.EncryptedGrant.parseFrom(encryptedGrantData);

        ByteString encryptedData = encryptedGrant.getEncryptedPhesk();

        // TODO: Add encryptedGrant.getHeader().toByteArray() as auth data
        byte[] key = this.cipher.decrypt(encryptedData.toByteArray(), this.ak);

        PurekitProtosV3.EncryptedGrantHeader header = PurekitProtosV3.EncryptedGrantHeader.parseFrom(encryptedGrant.getHeader());

        PureGrant grant = new PureGrant();

        grant.setSessionId(header.getSessionId());
        grant.setUserId(header.getUserId());
        grant.setCreationDate(new Date((long)header.getCreationDate() * 1000));
        grant.setPhesk(key);

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

    // TODO: How to update encrypted data?
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
            byte[] encrypted_csk = this.crypto.encrypt(cskData, Arrays.asList(upk));
            this.storage.insertKey(userId, dataId, cpkData, encrypted_csk);
            cpk = ckp.getPublicKey();
        }
        // FIXME: Catch only already exists error
        catch (Exception e) {
            // Key already exists
            CellKey cellKey = this.storage.selectKey(userId, dataId);

            cpk = this.crypto.importPublicKey(cellKey.getPublicKey());
        }

        // TODO: Add signature?
        return this.crypto.encrypt(plainText, Arrays.asList(cpk));
    }

    public byte[] decrypt(PureGrant grant, String dataId, byte[] cipherText) throws CryptoException {
        if (grant == null) {
            throw new NullPointerException();
        }
        if (dataId == null || dataId.isEmpty()) {
            throw new NullPointerException();
        }

        UserRecord userRecord = this.storage.selectUser(grant.getUserId());
        CellKey cellKey = this.storage.selectKey(grant.getUserId(), dataId);

        byte[] usk = this.cipher.decrypt(userRecord.getEncryptedUsk(), grant.getPhesk());

        VirgilKeyPair ukp = this.crypto.importPrivateKey(usk);

        byte[] csk = this.crypto.decrypt(cellKey.getEncryptedPrivateKey(), ukp.getPrivateKey());

        VirgilKeyPair ckp = this.crypto.importPrivateKey(csk);

        // TODO: Add signature?
        return this.crypto.decrypt(cipherText, ckp.getPrivateKey());
    }
}
