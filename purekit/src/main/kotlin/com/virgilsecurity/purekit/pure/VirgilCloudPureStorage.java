package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Crypto;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

/**
 * PureStorage on Virgil cloud side
 */
public class VirgilCloudPureStorage implements PureStorage {
    private VirgilCrypto crypto;
    private VirgilKeyPair signingKey;
    private HttpPureClient client;

    /**
     * Constructor
     * @param signingKey key used to sign data before sending to Virgil
     */
    public VirgilCloudPureStorage(HttpPureClient client, byte[] signingKey) throws CryptoException {
        if (client == null) {
            throw new NullPointerException();
        }
        if (signingKey == null) {
            throw new NullPointerException();
        }

        this.crypto = new VirgilCrypto();
        this.signingKey = this.crypto.importPrivateKey(signingKey);
        this.client = client;
    }

    private void sendUser(UserRecord userRecord, boolean isInsert) throws Exception {
        PurekitProtosV3Crypto.EnrollmentRecord enrollmentRecord = PurekitProtosV3Crypto.EnrollmentRecord.parseFrom(userRecord.getPheRecord());

        byte[] userRecordSigned = PurekitProtosV3Storage.UserRecordSigned.newBuilder()
                .setVersion(1) // FIXME
                .setUserId(userRecord.getUserId())
                .setPheRecordNs(enrollmentRecord.getNs())
                .setPheRecordNs(enrollmentRecord.getNc())
                .setUpk(ByteString.copyFrom(userRecord.getUpk()))
                .setEncryptedUsk(ByteString.copyFrom(userRecord.getEncryptedUsk()))
                .setEncryptedUskBackup(ByteString.copyFrom(userRecord.getEncryptedUskBackup()))
                .setEncryptedPwdHash(ByteString.copyFrom(userRecord.getEncryptedPwdHash()))
                .build()
                .toByteArray();

        byte[] signature = this.crypto.generateSignature(userRecordSigned, this.signingKey.getPrivateKey());

        PurekitProtosV3Storage.UserRecord protobufRecord = PurekitProtosV3Storage.UserRecord.newBuilder()
                .setVersion(1) /* FIXME */
                .setUserRecordSigned(ByteString.copyFrom(userRecordSigned))
                .setSignature(ByteString.copyFrom(signature))
                .setPheRecordT0(enrollmentRecord.getT0())
                .setPheRecordT1(enrollmentRecord.getT1())
                .setPheRecordVersion(userRecord.getPheRecordVersion())
                .build();

        try {
            if (isInsert) {
                this.client.insertUser(protobufRecord);
            }
            else {
                this.client.updateUser(protobufRecord);
            }
        }
        catch (ProtocolException | ProtocolHttpException e) {
            throw new Exception();
        }
    }

    /**
     * Inserts new User
     * @param userRecord User record
     * @throws Exception FIXME
     */
    @Override
    public void insertUser(UserRecord userRecord) throws Exception {
        this.sendUser(userRecord, true);
    }

    /**
     * Updates user
     * @param userRecord User record
     * @throws Exception FIXME
     */
    @Override
    public void updateUser(UserRecord userRecord) throws Exception {
        this.sendUser(userRecord, false);
    }

    /**
     * Obtains user
     * @param userId userId
     * @return UserRecord
     * @throws Exception FIXME
     */
    @Override
    public UserRecord selectUser(String userId) throws Exception {
        PurekitProtosV3Storage.UserRecord protobufRecord;

        try {
            protobufRecord = this.client.getUser(userId);
        }
        catch (ProtocolException | ProtocolHttpException e) {
            throw new Exception();
        }

        // TODO: Check version
        boolean verified = this.crypto.verifySignature(protobufRecord.getSignature().toByteArray(),
                protobufRecord.getUserRecordSigned().toByteArray(),
                this.signingKey.getPublicKey());

        if (!verified) {
            // FIXME
            throw new Exception();
        }

        PurekitProtosV3Storage.UserRecordSigned r = PurekitProtosV3Storage.UserRecordSigned.parseFrom(protobufRecord.getUserRecordSigned());

        byte[] pheRecord = PurekitProtosV3Crypto.EnrollmentRecord.newBuilder()
                .setNc(r.getPheRecordNc())
                .setNs(r.getPheRecordNs())
                .setT0(protobufRecord.getPheRecordT0())
                .setT1(protobufRecord.getPheRecordT1())
                .build()
                .toByteArray();

        return new UserRecord(r.getUserId(),
                pheRecord, protobufRecord.getPheRecordVersion(), r.getUpk().toByteArray(),
                r.getEncryptedUsk().toByteArray(), r.getEncryptedUskBackup().toByteArray(),
                r.getEncryptedPwdHash().toByteArray());
    }

    /**
     * This method throws NotImplementedException, as in case of using Virgil Cloud storage, rotation happens on Virgil side
     * @param pheRecordVersion PheRecordVersion
     * @return throws NotImplementedException
     * @throws NotImplementedException always
     */
    @Override
    public Iterable<UserRecord> selectUsers(int pheRecordVersion) throws NotImplementedException {
        // FIXME: Can we add message here?
        throw new NotImplementedException();
    }

    /**
     * Obtains key
     * @param userId userId
     * @param dataId dataId
     * @return CellKey
     * @throws Exception FIXME
     */
    @Override
    public CellKey selectKey(String userId, String dataId) throws Exception {

        PurekitProtosV3Storage.CellKey protobufRecord;

        try {
            protobufRecord = this.client.getCellKey(userId, dataId);
        }
        catch (ProtocolException | ProtocolHttpException e) {
            throw new Exception();
        }

        // TODO: Check version
        boolean verified = this.crypto.verifySignature(protobufRecord.getSignature().toByteArray(),
                protobufRecord.getCellKeySigned().toByteArray(),
                this.signingKey.getPublicKey());

        if (!verified) {
            // FIXME
            throw new Exception();
        }

        PurekitProtosV3Storage.CellKeySigned r = PurekitProtosV3Storage.CellKeySigned.parseFrom(protobufRecord.getCellKeySigned());

        return new CellKey(r.getCpk().toByteArray(), r.getEncryptedCskCms().toByteArray(), r.getEncryptedCskBody().toByteArray());
    }

    private void insertKey(String userId, String dataId, CellKey cellKey, boolean isInsert) throws Exception {
        byte[] cellKeySigned = PurekitProtosV3Storage.CellKeySigned.newBuilder()
                .setVersion(1) // FIXME
                .setUserId(userId)
                .setDataId(dataId)
                .setCpk(ByteString.copyFrom(cellKey.getCpk()))
                .setEncryptedCskCms(ByteString.copyFrom(cellKey.getEncryptedCskCms()))
                .setEncryptedCskBody(ByteString.copyFrom(cellKey.getEncryptedCskBody()))
                .build()
                .toByteArray();

        byte[] signature = this.crypto.generateSignature(cellKeySigned, this.signingKey.getPrivateKey());

        PurekitProtosV3Storage.CellKey protobufRecord = PurekitProtosV3Storage.CellKey.newBuilder()
                .setVersion(1) // FIXME
                .setCellKeySigned(ByteString.copyFrom(cellKeySigned))
                .setSignature(ByteString.copyFrom(signature))
                .build();

        try {
            if (isInsert) {
                this.client.insertCellKey(protobufRecord);
            }
            else {
                this.client.updateCellKey(protobufRecord);
            }
        }
        catch (ProtocolException | ProtocolHttpException e) {
            // FIXME: Check if it's already exists error and throw PureStorageKeyAlreadyExistsException
            throw new Exception();
        }
    }

    /**
     * Inserts new key
     * @param userId userId
     * @param dataId dataId
     * @param cellKey cell key record
     * @throws Exception FIXME
     */
    @Override
    public void insertKey(String userId, String dataId, CellKey cellKey) throws Exception {
        this.insertKey(userId, dataId, cellKey, true);
    }

    /**
     * Updates key
     * @param userId userId
     * @param dataId dataId
     * @param cellKey cell key record
     * @throws Exception FIXME
     */
    @Override
    public void updateKey(String userId, String dataId, CellKey cellKey) throws Exception {
        this.insertKey(userId, dataId, cellKey, false);
    }
}
