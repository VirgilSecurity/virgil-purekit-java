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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;

/**
 * PureStorage on Virgil cloud side
 */
public class VirgilCloudPureStorage implements PureStorage {
    private final VirgilCrypto crypto;
    private final VirgilKeyPair signingKey;
    private final HttpPureClient client;

    private static int currentUserVersion = 1;
    private static int currentUserSignedVersion = 1;
    private static int currentCellKeyVersion = 1;
    private static int currentCellKeySignedVersion = 1;

    /**
     * Constructor
     * @param signingKey key used to sign data before sending to Virgil
     */
    public VirgilCloudPureStorage(VirgilCrypto crypto, HttpPureClient client, VirgilKeyPair signingKey) throws CryptoException {
        if (crypto == null) {
            throw new NullPointerException();
        }
        if (client == null) {
            throw new NullPointerException();
        }
        if (signingKey == null) {
            throw new NullPointerException();
        }

        this.crypto = crypto;
        this.signingKey = signingKey;
        this.client = client;
    }

    private void sendUser(UserRecord userRecord, boolean isInsert) throws Exception {
        PurekitProtosV3Crypto.EnrollmentRecord enrollmentRecord = PurekitProtosV3Crypto.EnrollmentRecord.parseFrom(userRecord.getPheRecord());

        byte[] userRecordSigned = PurekitProtosV3Storage.UserRecordSigned.newBuilder()
                .setVersion(VirgilCloudPureStorage.currentUserSignedVersion)
                .setUserId(userRecord.getUserId())
                .setPheRecordNc(enrollmentRecord.getNc())
                .setPheRecordNs(enrollmentRecord.getNs())
                .setUpk(ByteString.copyFrom(userRecord.getUpk()))
                .setEncryptedUsk(ByteString.copyFrom(userRecord.getEncryptedUsk()))
                .setEncryptedUskBackup(ByteString.copyFrom(userRecord.getEncryptedUskBackup()))
                .setEncryptedPwdHash(ByteString.copyFrom(userRecord.getEncryptedPwdHash()))
                .build()
                .toByteArray();

        byte[] signature = this.crypto.generateSignature(userRecordSigned, this.signingKey.getPrivateKey());

        PurekitProtosV3Storage.UserRecord protobufRecord = PurekitProtosV3Storage.UserRecord.newBuilder()
                .setVersion(VirgilCloudPureStorage.currentUserVersion)
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
                this.client.updateUser(userRecord.getUserId(), protobufRecord);
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

    private UserRecord parse(PurekitProtosV3Storage.UserRecord protobufRecord) throws Exception {
        boolean verified = this.crypto.verifySignature(protobufRecord.getSignature().toByteArray(),
                protobufRecord.getUserRecordSigned().toByteArray(),
                this.signingKey.getPublicKey());

        if (!verified) {
            throw new PureException(PureException.ErrorCode.STORAGE_SIGNATURE_VERIFICATION_FAILED);
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
        catch (ProtocolException e) {
            if (e.getErrorCode() == HttpPureClient.ErrorCode.USER_NOT_FOUND.getErrorNumber()) {
                throw new PureException(PureException.ErrorCode.USER_NOT_FOUND_IN_STORAGE);
            }

            throw new Exception();
        }
        catch (ProtocolHttpException e) {
            throw new Exception();
        }

        UserRecord userRecord = this.parse(protobufRecord);

        if (!userRecord.getUserId().equals(userId)) {
            throw new PureException(PureException.ErrorCode.USER_ID_MISMATCH);
        }

        return userRecord;
    }

    /**
     * Obtains users record with given userId from storage
     * @param userIds userIds
     * @return UserRecords
     * @throws Exception FIXME
     */
    @Override
    public Iterable<UserRecord> selectUsers(Collection<String> userIds) throws Exception {
        HashSet<String> idsSet = new HashSet<>(userIds);

        if (idsSet.size() != userIds.size()) {
            throw new PureException(PureException.ErrorCode.DUPLICATE_USER_ID);
        }

        PurekitProtosV3Storage.UserRecords protobufRecords;

        try {
            protobufRecords = this.client.getUsers(userIds);
        }
        catch (ProtocolException | ProtocolHttpException e) {
            throw new Exception();
        }

        if (protobufRecords.getUserRecordsCount() != userIds.size()) {
            throw new PureException(PureException.ErrorCode.DUPLICATE_USER_ID);
        }

        ArrayList<UserRecord> userRecords = new ArrayList<>(protobufRecords.getUserRecordsCount());

        for (int i = 0; i < protobufRecords.getUserRecordsCount(); i++) {
            PurekitProtosV3Storage.UserRecord protobufRecord = protobufRecords.getUserRecords(i);

            UserRecord userRecord = this.parse(protobufRecord);

            if (!idsSet.contains(userRecord.getUserId())) {
                throw new PureException(PureException.ErrorCode.USER_ID_MISMATCH);
            }

            idsSet.remove(userRecord.getUserId());

            userRecords.add(userRecord);
        }

        return userRecords;
    }

    /**
     * This method throws NotImplementedException, as in case of using Virgil Cloud storage, rotation happens on Virgil side
     * @param pheRecordVersion PheRecordVersion
     * @return throws NotImplementedException
     * @throws NotImplementedException always
     */
    @Override
    public Iterable<UserRecord> selectUsers(int pheRecordVersion) throws NotImplementedException {
        // FIXME: Can we add message here? -> Specifically in this exception - no, but we can make similar custom one with message
        throw new NotImplementedException();
    }

    /**
     * Deletes user with given id
     * @param userId userId
     * @param cascade deletes all user cell keys if true
     * @throws Exception FIXME
     */
    @Override
    public void deleteUser(String userId, boolean cascade) throws Exception {
        try {
            this.client.deleteUser(userId, cascade);
        }
        catch (ProtocolException | ProtocolHttpException e) {
            throw new Exception();
        }
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
        catch (ProtocolException e) {
            if (e.getErrorCode() == HttpPureClient.ErrorCode.CELL_KEY_NOT_FOUND.getErrorNumber()) {
               return null;
            }

            throw new Exception();
        }
        catch (ProtocolHttpException e) {
            throw new Exception();
        }

        boolean verified = this.crypto.verifySignature(protobufRecord.getSignature().toByteArray(),
                protobufRecord.getCellKeySigned().toByteArray(),
                this.signingKey.getPublicKey());

        if (!verified) {
            throw new PureException(PureException.ErrorCode.STORAGE_SIGNATURE_VERIFICATION_FAILED);
        }

        PurekitProtosV3Storage.CellKeySigned r = PurekitProtosV3Storage.CellKeySigned.parseFrom(protobufRecord.getCellKeySigned());

        CellKey cellKey = new CellKey(r.getCpk().toByteArray(), r.getEncryptedCskCms().toByteArray(), r.getEncryptedCskBody().toByteArray());

        if (!userId.equals(r.getUserId()) || !dataId.equals(r.getDataId())) {
            throw new PureException(PureException.ErrorCode.USER_ID_MISMATCH);
        }

        return cellKey;
    }

    private void insertKey(String userId, String dataId, CellKey cellKey, boolean isInsert) throws Exception {
        byte[] cellKeySigned = PurekitProtosV3Storage.CellKeySigned.newBuilder()
                .setVersion(VirgilCloudPureStorage.currentCellKeySignedVersion)
                .setUserId(userId)
                .setDataId(dataId)
                .setCpk(ByteString.copyFrom(cellKey.getCpk()))
                .setEncryptedCskCms(ByteString.copyFrom(cellKey.getEncryptedCskCms()))
                .setEncryptedCskBody(ByteString.copyFrom(cellKey.getEncryptedCskBody()))
                .build()
                .toByteArray();

        byte[] signature = this.crypto.generateSignature(cellKeySigned, this.signingKey.getPrivateKey());

        PurekitProtosV3Storage.CellKey protobufRecord = PurekitProtosV3Storage.CellKey.newBuilder()
                .setVersion(VirgilCloudPureStorage.currentCellKeyVersion)
                .setCellKeySigned(ByteString.copyFrom(cellKeySigned))
                .setSignature(ByteString.copyFrom(signature))
                .build();

        try {
            if (isInsert) {
                try {
                    this.client.insertCellKey(protobufRecord);
                }
                catch (ProtocolException e) {
                    if (e.getErrorCode() == HttpPureClient.ErrorCode.CELL_KEY_ALREADY_EXISTS.getErrorNumber()) {
                        throw new PureException(PureException.ErrorCode.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
                    }

                    throw new Exception();
                }
            }
            else {
                this.client.updateCellKey(userId, dataId, protobufRecord);
            }
        }
        catch (ProtocolException | ProtocolHttpException e) {
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

    /**
     * Deletes cell key with given userId and dataId
     * @param userId userId
     * @param dataId dataId
     * @throws Exception FIXME
     */
    @Override
    public void deleteKey(String userId, String dataId) throws Exception {
        try {
            this.client.deleteCellKey(userId, dataId);
        }
        catch (ProtocolException | ProtocolHttpException e) {
            throw new Exception();
        }
    }
}
