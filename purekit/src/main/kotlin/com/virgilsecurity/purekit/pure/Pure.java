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

import java.nio.ByteBuffer;
import java.util.*;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.virgilsecurity.common.util.Base64;
import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Grant;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.storage.PureStorageCellKeyAlreadyExistsException;
import com.virgilsecurity.purekit.pure.storage.PureStorageCellKeyNotFoundException;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.pure.storage.PureStorage;
import com.virgilsecurity.purekit.utils.ValidateUtils;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;

/**
 * Main class for interactions with PureKit
 */
public class Pure {
    public static final long DEFAULT_GRANT_TTL = 60 * 60; // 1 hour

    private final static int currentGrantVersion = 1;

    private final int currentVersion;
    private final PureCrypto pureCrypto;
    private final PureStorage storage;
    private final VirgilPublicKey buppk;
    private final VirgilKeyPair oskp;
    private final Map<String, List<VirgilPublicKey>> externalPublicKeys;
    private final PheManager pheManager;
    private final KmsManager kmsManager;

    /**
     * Instantiates Pure.
     *
     * @param context PureContext.
     */
    public Pure(PureContext context) throws PureCryptoException {
        ValidateUtils.checkNull(context, "context");

        this.pureCrypto = new PureCrypto(context.getCrypto());
        this.storage = context.getStorage();
        this.buppk = context.getBuppk();
        this.oskp = context.getNonrotatableSecrets().getOskp();
        this.externalPublicKeys = context.getExternalPublicKeys();
        this.pheManager = new PheManager(context);
        this.kmsManager = new KmsManager(context);

        if (context.getUpdateToken() != null) {
            this.currentVersion = context.getPublicKey().getVersion() + 1;
        }
        else {
            this.currentVersion = context.getPublicKey().getVersion();
        }
    }

    /**
     * Registers new user.
     *
     * @param userId User Id.
     * @param password Password.
     *
     * @throws PureException PureException
     *
     */
    public void registerUser(String userId, String password) throws PureException {
        registerUserInternal(userId, password, true);
    }

    /**
     * Registers and authenticates new user.
     *
     * @param userId User Id.
     * @param password Password.
     * @param pureSessionParams pureSessionParams
     *
     * @throws PureException PureException
     *
     */
    public AuthResult registerUser(String userId, String password, PureSessionParams pureSessionParams) throws PureException {

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(password, "password");
        ValidateUtils.checkNull(pureSessionParams, "pureSessionParams");

        RegisterResult registerResult = registerUserInternal(userId, password, true);

        return authenticateUserInternal(registerResult.getUserRecord(), registerResult.getUkp(),
                registerResult.getPhek(), pureSessionParams.getSessionId(), pureSessionParams.getTtl());
    }

    /**
     * Authenticates user.
     *
     * @param userId User Id.
     * @param password Password.
     * @param pureSessionParams pureSessionParams
     *
     * @return AuthResult with PureGrant and encrypted PureGrant.
     *
     * @throws PureException PureException
     */
    public AuthResult authenticateUser(String userId, String password, PureSessionParams pureSessionParams) throws PureException {

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(password, "password");
        ValidateUtils.checkNull(pureSessionParams, "pureSessionParams");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] phek = pheManager.computePheKey(userRecord, password);

        byte[] uskData = pureCrypto.decryptSymmetricWithNewNonce(userRecord.getEncryptedUsk(), new byte[0], phek);

        VirgilKeyPair ukp = pureCrypto.importPrivateKey(uskData);

        return authenticateUserInternal(userRecord, ukp, phek, pureSessionParams.getSessionId(), pureSessionParams.getTtl());
    }

    /**
     * Authenticates user.
     *
     * @param userId User Id.
     * @param password Password.
     *
     * @return AuthResult with PureGrant and encrypted PureGrant.
     *
     * @throws PureException PureException
     */
    public AuthResult authenticateUser(String userId, String password) throws PureException {

        return authenticateUser(userId, password, new PureSessionParams());
    }

    /**
     * Invalidates existing encrypted user grant
     *
     * @param encryptedGrantString encryptedGrantString
     *
     * @throws PureException PureException
     */
    public void invalidateEncryptedUserGrant(String encryptedGrantString) throws PureException {
        DeserializedEncryptedGrant deserializedEncryptedGrant = deserializeEncryptedGrant(encryptedGrantString);

        // Just to check that grant was valid
        decryptPheKeyFromEncryptedGrant(deserializedEncryptedGrant);

        storage.deleteGrantKey(deserializedEncryptedGrant.getHeader().getUserId(),
                deserializedEncryptedGrant.getHeader().getKeyId().toByteArray());
    }

    /**
     * Creates PureGrant for some user using admin backup private key.
     *
     * @param userId User Id.
     * @param bupsk Admin backup private key.
     * @param ttl time to live in seconds
     *
     * @return PureGrant.
     *
     * @throws PureException PureException
     */
    public PureGrant createUserGrantAsAdmin(String userId, VirgilPrivateKey bupsk, long ttl) throws PureException {

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNull(bupsk, "bupsk");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] usk = pureCrypto.decryptBackup(userRecord.getEncryptedUskBackup(), bupsk, oskp.getPublicKey());

        VirgilKeyPair upk = pureCrypto.importPrivateKey(usk);

        Date creationDate = new Date();
        Date expirationDate = new Date(creationDate.getTime() + ttl * 1000);

        return new PureGrant(upk, userId, null, creationDate, expirationDate);
    }

    /**
     * Creates PureGrant for some user using admin backup private key.
     *
     * @param userId User Id.
     * @param bupsk Admin backup private key.
     *
     * @return PureGrant.
     *
     * @throws PureException PureException
     */
    public PureGrant createUserGrantAsAdmin(String userId, VirgilPrivateKey bupsk) throws PureException {
        return createUserGrantAsAdmin(userId, bupsk, DEFAULT_GRANT_TTL);
    }

    static class DeserializedEncryptedGrant {
        private final PurekitProtosV3Grant.EncryptedGrant encryptedGrant;
        private final PurekitProtosV3Grant.EncryptedGrantHeader header;

        DeserializedEncryptedGrant(PurekitProtosV3Grant.EncryptedGrant encryptedGrant, PurekitProtosV3Grant.EncryptedGrantHeader header) {
            this.encryptedGrant = encryptedGrant;
            this.header = header;
        }

        PurekitProtosV3Grant.EncryptedGrant getEncryptedGrant() {
            return encryptedGrant;
        }

        PurekitProtosV3Grant.EncryptedGrantHeader getHeader() {
            return header;
        }
    }

    private DeserializedEncryptedGrant deserializeEncryptedGrant(String encryptedGrantString)  throws PureException {
        ValidateUtils.checkNullOrEmpty(encryptedGrantString, "encryptedGrantString");

        byte[] encryptedGrantData = Base64.decode(encryptedGrantString.getBytes());

        PurekitProtosV3Grant.EncryptedGrant encryptedGrant;
        try {
            encryptedGrant = PurekitProtosV3Grant.EncryptedGrant.parseFrom(encryptedGrantData);
        } catch (InvalidProtocolBufferException e) {
            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_INVALID_PROTOBUF);
        }

        PurekitProtosV3Grant.EncryptedGrantHeader header;
        try {
            header = PurekitProtosV3Grant.EncryptedGrantHeader.parseFrom(encryptedGrant.getHeader());
        } catch (InvalidProtocolBufferException e) {
            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_INVALID_PROTOBUF);
        }

        return new DeserializedEncryptedGrant(encryptedGrant, header);
    }

    private byte[] decryptPheKeyFromEncryptedGrant(DeserializedEncryptedGrant deserializedEncryptedGrant) throws PureException {
        ByteString encryptedData = deserializedEncryptedGrant.getEncryptedGrant().getEncryptedPhek();

        GrantKey grantKey = storage.selectGrantKey(deserializedEncryptedGrant.getHeader().getUserId(),
                deserializedEncryptedGrant.getHeader().getKeyId().toByteArray());

        if (grantKey.getExpirationDate().before(new Date())) {
            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_IS_EXPIRED);
        }

        byte[] grantKeyRaw = kmsManager.recoverGrantKey(grantKey, deserializedEncryptedGrant.getHeader().toByteArray());

        return pureCrypto.decryptSymmetricWithOneTimeKey(encryptedData.toByteArray(),
                deserializedEncryptedGrant.getHeader().toByteArray(),
                grantKeyRaw);
    }

    /**
     * Decrypt encrypted PureGrant that was stored on client-side.
     *
     * @param encryptedGrantString Encrypted PureGrant obtained from authenticateUser method.
     *
     * @return PureGrant.
     *
     * @throws PureException PureException
     */
    public PureGrant decryptGrantFromUser(String encryptedGrantString) throws PureException {
        DeserializedEncryptedGrant deserializedEncryptedGrant = deserializeEncryptedGrant(encryptedGrantString);

        byte[] phek = decryptPheKeyFromEncryptedGrant(deserializedEncryptedGrant);

        UserRecord userRecord = storage.selectUser(deserializedEncryptedGrant.getHeader().getUserId());

        byte[] usk = pureCrypto.decryptSymmetricWithNewNonce(userRecord.getEncryptedUsk(), new byte[0], phek);

        VirgilKeyPair ukp = pureCrypto.importPrivateKey(usk);

        String sessionId = deserializedEncryptedGrant.getHeader().getSessionId();

        if (sessionId.isEmpty()) {
            sessionId = null;
        }

        return new PureGrant(ukp,
                deserializedEncryptedGrant.getHeader().getUserId(),
                sessionId,
                new Date((long) (deserializedEncryptedGrant.getHeader().getCreationDate()) * 1000),
                new Date((long) (deserializedEncryptedGrant.getHeader().getExpirationDate()) * 1000));
    }

    /**
     * Changes user password. All encrypted data remains accessible after this method call.
     *
     * @param userId UserId.
     * @param oldPassword Old password.
     * @param newPassword New password.
     *
     * @throws PureException PureException
     */
    public void changeUserPassword(String userId, String oldPassword, String newPassword) throws PureException {

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(oldPassword, "oldPassword");
        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] oldPhek = pheManager.computePheKey(userRecord, oldPassword);

        byte[] privateKeyData = pureCrypto.decryptSymmetricWithNewNonce(userRecord.getEncryptedUsk(), new byte[0], oldPhek);

        changeUserPasswordInternal(userRecord, privateKeyData, newPassword);
    }

    /**
     * Changes user password. All encrypted data remains accessible after this method call.
     *
     * @param grant PureGrant obtained either using {@link Pure#authenticateUser} or
     *              {@link Pure#createUserGrantAsAdmin}.
     * @param newPassword New password.
     *
     * @throws PureException PureException
     */
    public void changeUserPassword(PureGrant grant, String newPassword) throws PureException {

        ValidateUtils.checkNull(grant, "grant");
        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        UserRecord userRecord = storage.selectUser(grant.getUserId());

        byte[] privateKeyData = pureCrypto.exportPrivateKey(grant.getUkp().getPrivateKey());

        changeUserPasswordInternal(userRecord, privateKeyData, newPassword);
    }

    /**
     * Recovers user in case he doesn't remember his password
     *
     * Note: this method is under server-side rate-limiting, which prevents adversary from decrypting database.
     *
     * @param userId userId
     * @param newPassword new password
     *
     * @throws PureException PureException
     */
    public void recoverUser(String userId, String newPassword) throws PureException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] pwdHash = kmsManager.recoverPwd(userRecord);

        byte[] oldPhek = pheManager.computePheKey(userRecord, pwdHash);

        byte[] privateKeyData = pureCrypto.decryptSymmetricWithNewNonce(userRecord.getEncryptedUsk(), new byte[0], oldPhek);

        changeUserPasswordInternal(userRecord, privateKeyData, newPassword);
    }

    /**
     * Resets user password, all encrypted user data becomes inaccessible.
     *
     * @param userId User id.
     * @param newPassword New password.
     *
     * @throws PureException PureException
     */
    public void resetUserPassword(String userId, String newPassword) throws PureException {
        // TODO: Add possibility to delete cell keys? -> ????
        registerUserInternal(userId, newPassword, false);
    }

    /**
     * Deletes user with given id.
     *
     * @param userId User Id.
     * @param cascade Deletes all user cell keys if true.
     *
     * @throws PureException PureException
     */
    public void deleteUser(String userId, boolean cascade) throws PureException {

        storage.deleteUser(userId, cascade);
        // TODO: Should delete role assignments
    }

    /**
     * Rotation result
     */
    public static class RotationResults {
        private final long usersRotated;
        private final long grantKeysRotated;

        /**
         * Constructor
         *
         * @param usersRotated number of users that were rotated
         * @param grantKeysRotated number of grant keys that were rotated
         */
        public RotationResults(long usersRotated, long grantKeysRotated) {
            this.usersRotated = usersRotated;
            this.grantKeysRotated = grantKeysRotated;
        }

        /**
         * Returns number of users that were rotated
         *
         * @return number of users that were rotated
         */
        public long getUsersRotated() {
            return usersRotated;
        }

        /**
         * Returns number of grant keys that were rotated
         *
         * @return number of grant keys that were rotated
         */
        public long getGrantKeysRotated() {
            return grantKeysRotated;
        }
    }

    /**
     * Performs PHE and KMS records rotation for all users with old version.
     * Pure should be initialized with UpdateToken for this operation.
     *
     * @return Number of rotated records.
     *
     * @throws PureException PureException
     */
    public RotationResults performRotation() throws PureException {
        if (currentVersion <= 1) {
            return new RotationResults(0, 0);
        }

        long usersRotated = 0;
        long grantKeysRotated = 0;

        while (true) {
            Iterable<UserRecord> userRecords = storage.selectUsers(currentVersion - 1);
            ArrayList<UserRecord> newUserRecords = new ArrayList<>();

            for (UserRecord userRecord: userRecords) {
                assert userRecord.getRecordVersion() == currentVersion - 1;

                byte[] newRecord = pheManager.performRotation(userRecord.getPheRecord());
                byte[] newWrap = kmsManager.performPwdRotation(userRecord.getPasswordRecoveryWrap());

                UserRecord newUserRecord = new UserRecord(
                    userRecord.getUserId(),
                    newRecord,
                    currentVersion,
                    userRecord.getUpk(),
                    userRecord.getEncryptedUsk(),
                    userRecord.getEncryptedUskBackup(),
                    userRecord.getBackupPwdHash(),
                    newWrap,
                    userRecord.getPasswordRecoveryBlob()
                );

                newUserRecords.add(newUserRecord);
            }

            storage.updateUsers(newUserRecords, currentVersion - 1);

            if (newUserRecords.isEmpty()) {
                break;
            }
            else {
                usersRotated += newUserRecords.size();
            }
        }

        while (true) {
            Iterable<GrantKey> grantKeys = storage.selectGrantKeys(currentVersion - 1);
            ArrayList<GrantKey> newGrantKeys = new ArrayList<>();

            for (GrantKey grantKey: grantKeys) {
                assert grantKey.getRecordVersion() == currentVersion - 1;

                byte[] newWrap = kmsManager.performGrantRotation(grantKey.getEncryptedGrantKeyWrap());

                GrantKey newGrantKey = new GrantKey(
                        grantKey.getUserId(),
                        grantKey.getKeyId(),
                        currentVersion,
                        newWrap,
                        grantKey.getEncryptedGrantKeyBlob(),
                        grantKey.getCreationDate(),
                        grantKey.getExpirationDate()
                );

                newGrantKeys.add(newGrantKey);
            }

            storage.updateGrantKeys(newGrantKeys);

            if (newGrantKeys.isEmpty()) {
                break;
            }
            else {
                grantKeysRotated += newGrantKeys.size();
            }
        }

        return new RotationResults(usersRotated, grantKeysRotated);
    }

    /**
     * Encrypts data.
     *
     * This method generates keypair that is unique for given userId and dataId, encrypts plainText
     * using this keypair and stores public key and encrypted private key. Multiple encryptions for
     * the same userId and dataId are allowed, in this case existing keypair will be used.
     *
     * @param userId User Id of data owner.
     * @param dataId DataId.
     * @param plainText Plain text.
     *
     * @return Cipher text.
     *
     * @throws PureException PureException
     */
    public byte[] encrypt(String userId, String dataId, byte[] plainText) throws PureException {

        return encrypt(userId,
                       dataId,
                       Collections.emptySet(),
                       Collections.emptySet(),
                       Collections.emptySet(),
                       plainText);
    }

    /**
     * Encrypts data.
     *
     * This method generates keypair that is unique for given userId and dataId, encrypts plainText
     * using this keypair and stores public key and encrypted private key. Multiple encryptions for
     * the same userId and dataId are allowed, in this case existing keypair will be used.
     *
     * @param userId User Id of data owner.
     * @param dataId Data Id.
     * @param otherUserIds Other user ids, to whom access to this data will be given.
     * @param publicKeys Other public keys, to which access to this data will be given.
     * @param plainText Plain text.
     *
     * @return Cipher text.
     *
     * @throws PureException PureException
     */
    public byte[] encrypt(String userId,
                          String dataId,
                          Set<String> otherUserIds,
                          Set<String> roleNames,
                          Collection<VirgilPublicKey> publicKeys,
                          byte[] plainText) throws PureException {

        ValidateUtils.checkNull(otherUserIds, "otherUserIds");
        ValidateUtils.checkNull(publicKeys, "publicKeys");
        ValidateUtils.checkNull(plainText, "plainText");

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        VirgilPublicKey cpk;

        // Key already exists
        try {
            CellKey cellKey = storage.selectCellKey(userId, dataId);
            cpk = pureCrypto.importPublicKey(cellKey.getCpk());
        }
        catch (PureStorageCellKeyNotFoundException e) {
            // Try to generate and save new key
            try {
                ArrayList<VirgilPublicKey> recipientList = new ArrayList<>(
                    externalPublicKeys.size() + publicKeys.size() + otherUserIds.size() + roleNames.size() + 1
                );

                recipientList.addAll(publicKeys);

                HashSet<String> userIds = new HashSet<>(1 + otherUserIds.size());
                userIds.add(userId);
                userIds.addAll(otherUserIds);

                Iterable<UserRecord> userRecords = storage.selectUsers(userIds);

                for (UserRecord record : userRecords) {
                    VirgilPublicKey otherUpk = pureCrypto.importPublicKey(record.getUpk());
                    recipientList.add(otherUpk);
                }

                Iterable<Role> roles = storage.selectRoles(roleNames);

                for (Role role: roles) {
                    VirgilPublicKey rpk = pureCrypto.importPublicKey(role.getRpk());
                    recipientList.add(rpk);
                }

                List<VirgilPublicKey> externalPublicKeys = this.externalPublicKeys.get(dataId);

                if (externalPublicKeys != null) {
                    recipientList.addAll(externalPublicKeys);
                }

                VirgilKeyPair ckp = pureCrypto.generateCellKey();
                byte[] cpkData = pureCrypto.exportPublicKey(ckp.getPublicKey());
                byte[] cskData = pureCrypto.exportPrivateKey(ckp.getPrivateKey());

                PureCryptoData encryptedCskData = pureCrypto.encryptCellKey(cskData, recipientList, oskp.getPrivateKey());

                CellKey cellKey = new CellKey(userId, dataId, cpkData, encryptedCskData.getCms(), encryptedCskData.getBody());

                storage.insertCellKey(cellKey);
                cpk = ckp.getPublicKey();
            } catch (PureStorageCellKeyAlreadyExistsException e1) {
                CellKey cellKey = storage.selectCellKey(userId, dataId);

                cpk = pureCrypto.importPublicKey(cellKey.getCpk());
            }
        }

        return pureCrypto.encryptData(plainText, Collections.singletonList(cpk), oskp.getPrivateKey());
    }

    /**
     * Decrypts data.
     *
     * @param grant User PureGrant obtained using {@link Pure#authenticateUser} or
     *             {@link Pure#createUserGrantAsAdmin} methods.
     * @param ownerUserId Owner userId, pass null if PureGrant belongs to.
     * @param dataId Data Id that was used during encryption.
     * @param cipherText Cipher text.
     *
     * @return Plain text.
     *
     * @throws PureException PureException
     */
    public byte[] decrypt(PureGrant grant, String ownerUserId, String dataId, byte[] cipherText) throws PureException {

        ValidateUtils.checkNull(grant, "grant");
        ValidateUtils.checkNull(cipherText, "cipherText");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        String userId = ownerUserId;

        if (userId == null) {
            userId = grant.getUserId();
        }

        CellKey cellKey = storage.selectCellKey(userId, dataId);

        PureCryptoData pureCryptoData = new PureCryptoData(cellKey.getEncryptedCskCms(),
                cellKey.getEncryptedCskBody());

        byte[] csk = null;

        try {
            csk = pureCrypto.decryptCellKey(pureCryptoData, grant.getUkp().getPrivateKey(), oskp.getPublicKey());
        }
        catch (PureCryptoException e) {
            if (e.getFoundationException() == null || e.getFoundationException().getStatusCode() != FoundationException.ERROR_KEY_RECIPIENT_IS_NOT_FOUND) {
                throw e;
            }

            Iterable<RoleAssignment> roleAssignments = storage.selectRoleAssignments(grant.getUserId());

            // TODO: Replace ByteBuffer
            Set<ByteBuffer> publicKeysIds = pureCrypto.extractPublicKeysIdsFromCellKey(cellKey.getEncryptedCskCms());

            for (RoleAssignment roleAssignment: roleAssignments) {
                ByteBuffer publicKeyId = ByteBuffer.wrap(roleAssignment.getPublicKeyId());

                if (publicKeysIds.contains(publicKeyId)) {
                    byte[] rskData = pureCrypto.decryptRolePrivateKey(roleAssignment.getEncryptedRsk(), grant.getUkp().getPrivateKey(), oskp.getPublicKey());

                    VirgilKeyPair rkp = pureCrypto.importPrivateKey(rskData);

                    csk = pureCrypto.decryptCellKey(pureCryptoData, rkp.getPrivateKey(), oskp.getPublicKey());
                    break;
                }
            }

            if (csk == null) {
                throw new PureLogicException(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA);
            }
        }

        VirgilKeyPair ckp = pureCrypto.importPrivateKey(csk);

        return pureCrypto.decryptData(cipherText, ckp.getPrivateKey(), oskp.getPublicKey());
    }

    /**
     * Decrypts data.
     *
     * @param privateKey Private key from corresponding public key that was used during
     * {@link Pure#encrypt}, {@link Pure#share} on present in externalPublicKeys.
     * @param ownerUserId Owner userId, pass null if PureGrant belongs to.
     * @param dataId Data Id that was used during encryption.
     * @param cipherText Cipher text.
     *
     * @return Plain text.
     *
     * @throws PureException PureException
     */
    public byte[] decrypt(VirgilPrivateKey privateKey,
                          String ownerUserId,
                          String dataId,
                          byte[] cipherText) throws PureException {

        // TODO: Delete copy&paste

        ValidateUtils.checkNull(privateKey, "privateKey");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");
        ValidateUtils.checkNullOrEmpty(ownerUserId, "ownerUserId");

        CellKey cellKey = storage.selectCellKey(ownerUserId, dataId);

        PureCryptoData pureCryptoData = new PureCryptoData(cellKey.getEncryptedCskCms(),
                cellKey.getEncryptedCskBody());

        byte[] csk = pureCrypto.decryptCellKey(pureCryptoData, privateKey, oskp.getPublicKey());

        VirgilKeyPair ckp = pureCrypto.importPrivateKey(csk);

        return pureCrypto.decryptData(cipherText, ckp.getPrivateKey(), oskp.getPublicKey());
    }

    /**
     * Gives possibility to decrypt data to other user that is not data owner. Shared data can then
     * be decrypted using other user's PureGrant.
     *
     * @param grant PureGrant of data owner.
     * @param dataId Data Id.
     * @param otherUserId User Id of user to whom access is given.
     *
     * @throws PureException PureException
     */
    public void share(PureGrant grant, String dataId, String otherUserId) throws PureException {

        ValidateUtils.checkNull(grant, "grant");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");
        ValidateUtils.checkNullOrEmpty(otherUserId, "otherUserId");

        share(grant, dataId, Collections.singleton(otherUserId), Collections.emptyList());
    }

    /**
     * Gives possibility to decrypt data to other user that is not data owner.
     * Shared data can then be decrypted using other user's PureGrant.
     *
     * @param grant PureGrant of data owner.
     * @param dataId Data Id.
     * @param otherUserIds Other user Ids.
     * @param publicKeys Public keys to share data with.
     *
     * @throws PureException PureException
     */
    public void share(PureGrant grant,
                      String dataId,
                      Set<String> otherUserIds,
                      Collection<VirgilPublicKey> publicKeys) throws PureException {

        ValidateUtils.checkNull(grant, "grant");
        ValidateUtils.checkNull(otherUserIds, "otherUserIds");
        ValidateUtils.checkNull(publicKeys, "publicKeys");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        ArrayList<VirgilPublicKey> keys = keysWithOthers(publicKeys, otherUserIds);
        CellKey cellKey = storage.selectCellKey(grant.getUserId(), dataId);

        byte[] encryptedCskCms = pureCrypto.addRecipientsToCellKey(cellKey.getEncryptedCskCms(),
                                                                   grant.getUkp().getPrivateKey(),
                                                                   keys);

        CellKey cellKeyNew = new CellKey(cellKey.getUserId(), cellKey.getDataId(),
                                         cellKey.getCpk(), encryptedCskCms,
                                         cellKey.getEncryptedCskBody());

        storage.updateCellKey(cellKeyNew);
    }

    /**
     * Revoke possibility to decrypt data from other user that is not data owner.
     * It won't be possible to decrypt such data other user's PureGrant.
     * Note, that even if further decrypt calls will not succeed for other user,
     * he could have made a copy of decrypted data before that call.
     *
     * @param ownerUserId Data owner user Id.
     * @param dataId DataId.
     * @param otherUserId User Id of user to whom access is taken away.
     *
     * @throws PureException PureException
     */
    public void unshare(String ownerUserId, String dataId, String otherUserId) throws PureException {

        unshare(ownerUserId,
                dataId,
                Collections.singleton(otherUserId),
                Collections.emptyList());
    }

    /**
     * Revoke possibility to decrypt data from other user that is not data owner.
     * It won't be possible to decrypt such data other user's PureGrant.
     * Note, that even if further decrypt calls will not succeed for other user,
     * he could have made a copy of decrypted data before that call.
     *
     * @param ownerUserId Data owner user Id.
     * @param dataId DataId.
     * @param otherUserIds Other user ids that are being removed from share list.
     * @param publicKeys Public keys that are being removed from share list.
     *
     * @throws PureException PureException
     */
    public void unshare(String ownerUserId,
                        String dataId,
                        Set<String> otherUserIds,
                        Collection<VirgilPublicKey> publicKeys) throws PureException {

        ValidateUtils.checkNull(otherUserIds, "otherUserIds");
        ValidateUtils.checkNull(publicKeys, "publicKeys");

        ValidateUtils.checkNullOrEmpty(ownerUserId, "ownerUserId");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        ArrayList<VirgilPublicKey> keys = keysWithOthers(publicKeys, otherUserIds);

        CellKey cellKey = storage.selectCellKey(ownerUserId, dataId);

        byte[] encryptedCskCms = pureCrypto.deleteRecipientsFromCellKey(cellKey.getEncryptedCskCms(), keys);

        CellKey cellKeyNew = new CellKey(cellKey.getUserId(), cellKey.getDataId(),
                                         cellKey.getCpk(), encryptedCskCms,
                                         cellKey.getEncryptedCskBody());

        storage.updateCellKey(cellKeyNew);
    }

    /**
     * Deletes cell key with given user Id and data Id.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @throws PureException PureException
     */
    public void deleteKey(String userId, String dataId) throws PureException {

        storage.deleteCellKey(userId, dataId);
    }

    /**
     * Creates role
     *
     * @param roleName role name
     * @param userIds user ids that belong to role
     *
     * @throws PureException PureException
     */
    public void createRole(String roleName, Set<String> userIds) throws PureException {
        VirgilKeyPair rkp = pureCrypto.generateRoleKey();
        byte[] rpkData = pureCrypto.exportPublicKey(rkp.getPublicKey());
        byte[] rskData = pureCrypto.exportPrivateKey(rkp.getPrivateKey());

        Role role = new Role(roleName, rpkData);

        storage.insertRole(role);

        assignRole(roleName, rkp.getPublicKey().getIdentifier(), rskData, userIds);
    }

    /**
     * Assigns users to role
     *
     * @param roleToAssign role name
     * @param grant grant of one of users, that are already assigned to this role
     * @param userIds user ids of users who will be assigned to this role
     * @throws PureException PureException
     */
    public void assignRole(String roleToAssign, PureGrant grant, Set<String> userIds) throws PureException {
        RoleAssignment roleAssignment = storage.selectRoleAssignment(roleToAssign, grant.getUserId());

        byte[] rskData = pureCrypto.decryptRolePrivateKey(roleAssignment.getEncryptedRsk(), grant.getUkp().getPrivateKey(), oskp.getPublicKey());

        assignRole(roleToAssign, roleAssignment.getPublicKeyId(), rskData, userIds);
    }

    private void assignRole(String roleName, byte[] publicKeyId, byte[] rskData, Set<String> userIds) throws PureException {
        Iterable<UserRecord> userRecords = storage.selectUsers(userIds);

        ArrayList<RoleAssignment> roleAssignments = new ArrayList<>(userIds.size());

        for (UserRecord userRecord: userRecords) {
            VirgilPublicKey upk = pureCrypto.importPublicKey(userRecord.getUpk());

            byte[] encryptedRsk = pureCrypto.encryptRolePrivateKey(rskData, upk, oskp.getPrivateKey());

            roleAssignments.add(new RoleAssignment(roleName, userRecord.getUserId(), publicKeyId, encryptedRsk));
        }

        storage.insertRoleAssignments(roleAssignments);
    }

    /**
     * Unassigns users from role
     *
     * @param roleName role name
     * @param userIds user ids
     * @throws PureException PureException
     */
    public void unassignRole(String roleName, Set<String> userIds) throws PureException {
        storage.deleteRoleAssignments(roleName, userIds);
    }

    static class RegisterResult {
        private final UserRecord userRecord;
        private final VirgilKeyPair ukp;
        private final byte[] phek;

        public RegisterResult(UserRecord userRecord, VirgilKeyPair ukp, byte[] phek) {
            this.userRecord = userRecord;
            this.ukp = ukp;
            this.phek = phek;
        }

        public UserRecord getUserRecord() {
            return userRecord;
        }

        public VirgilKeyPair getUkp() {
            return ukp;
        }

        public byte[] getPhek() {
            return phek;
        }
    }

    private RegisterResult registerUserInternal(String userId, String password, boolean isUserNew) throws PureException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(password, "password");

        byte[] passwordHash = pureCrypto.computePasswordHash(password);

        byte[] encryptedPwdHash = pureCrypto.encryptForBackup(passwordHash, buppk, oskp.getPrivateKey());

        KmsManager.KmsEncryptedData pwdRecoveryData = kmsManager.generatePwdRecoveryData(passwordHash);

        PheClientEnrollAccountResult pheResult = pheManager.getEnrollment(passwordHash);

        VirgilKeyPair ukp = pureCrypto.generateUserKey();

        byte[] uskData = pureCrypto.exportPrivateKey(ukp.getPrivateKey());

        byte[] encryptedUsk = pureCrypto.encryptSymmetricWithNewNonce(uskData, new byte[0], pheResult.getAccountKey());

        byte[] encryptedUskBackup = pureCrypto.encryptForBackup(uskData, buppk, oskp.getPrivateKey());

        byte[] publicKey = pureCrypto.exportPublicKey(ukp.getPublicKey());

        UserRecord userRecord = new UserRecord(
            userId,
            pheResult.getEnrollmentRecord(),
            currentVersion,
            publicKey,
            encryptedUsk,
            encryptedUskBackup,
            encryptedPwdHash,
            pwdRecoveryData.getWrap(),
            pwdRecoveryData.getBlob()
        );

        if (isUserNew) {
            storage.insertUser(userRecord);
        } else {
            storage.updateUser(userRecord);
        }

        return new RegisterResult(userRecord, ukp, pheResult.getAccountKey());
    }

    private AuthResult authenticateUserInternal(UserRecord userRecord, VirgilKeyPair ukp, byte[] phek, String sessionId, long ttl) throws PureException {
        Date creationDate = new Date();
        Date expirationDate = new Date(creationDate.getTime() + ttl * 1000);

        PureGrant grant = new PureGrant(ukp, userRecord.getUserId(), sessionId, creationDate, expirationDate);

        byte[] grantKeyRaw = pureCrypto.generateSymmetricOneTimeKey();
        byte[] keyId = pureCrypto.computeSymmetricKeyId(grantKeyRaw);

        PurekitProtosV3Grant.EncryptedGrantHeader.Builder headerBuilder =
                PurekitProtosV3Grant.EncryptedGrantHeader.newBuilder()
                        .setCreationDate((int) (grant.getCreationDate().getTime() / 1000))
                        .setExpirationDate((int) (grant.getExpirationDate().getTime() / 1000))
                        .setUserId(grant.getUserId())
                        .setKeyId(ByteString.copyFrom(keyId));

        if (sessionId != null) {
            headerBuilder.setSessionId(sessionId);
        }

        PurekitProtosV3Grant.EncryptedGrantHeader header = headerBuilder.build();

        byte[] headerBytes = header.toByteArray();

        KmsManager.KmsEncryptedData grantWrap = kmsManager.generateGrantKeyEncryptionData(grantKeyRaw, headerBytes);

        GrantKey grantKey = new GrantKey(userRecord.getUserId(),
                keyId, currentVersion,
                grantWrap.getWrap(),
                grantWrap.getBlob(),
                creationDate, expirationDate);

        storage.insertGrantKey(grantKey);

        byte[] encryptedPhek = pureCrypto.encryptSymmetricWithOneTimeKey(phek, headerBytes, grantKeyRaw);

        PurekitProtosV3Grant.EncryptedGrant encryptedGrantData =
                PurekitProtosV3Grant.EncryptedGrant.newBuilder()
                        .setVersion(Pure.currentGrantVersion)
                        .setHeader(ByteString.copyFrom(headerBytes))
                        .setEncryptedPhek(ByteString.copyFrom(encryptedPhek))
                        .build();

        String encryptedGrant = Base64.encode(encryptedGrantData.toByteArray());

        return new AuthResult(grant, encryptedGrant);
    }

    private void changeUserPasswordInternal(UserRecord userRecord,
                                            byte[] privateKeyData,
                                            String newPassword) throws PureException {

        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        byte[] newPasswordHash = pureCrypto.computePasswordHash(newPassword);

        PheClientEnrollAccountResult enrollResult = pheManager.getEnrollment(newPasswordHash);

        KmsManager.KmsEncryptedData pwdRecoveryData = kmsManager.generatePwdRecoveryData(newPasswordHash);

        byte[] newEncryptedUsk = pureCrypto.encryptSymmetricWithNewNonce(privateKeyData, new byte[0], enrollResult.getAccountKey());

        byte[] encryptedPwdHash = pureCrypto.encryptForBackup(newPasswordHash, buppk, oskp.getPrivateKey());

        UserRecord newUserRecord = new UserRecord(
            userRecord.getUserId(),
            enrollResult.getEnrollmentRecord(),
            currentVersion,
            userRecord.getUpk(),
            newEncryptedUsk,
            userRecord.getEncryptedUskBackup(),
            encryptedPwdHash,
            pwdRecoveryData.getWrap(),
            pwdRecoveryData.getBlob()
        );

        storage.updateUser(newUserRecord);
    }

    private ArrayList<VirgilPublicKey> keysWithOthers(Collection<VirgilPublicKey> publicKeys,
                                                      Set<String> otherUserIds) throws PureException {

        ArrayList<VirgilPublicKey> keys = new ArrayList<>(publicKeys);

        Iterable<UserRecord> otherUserRecords = storage.selectUsers(otherUserIds);

        for (UserRecord record : otherUserRecords) {
            VirgilPublicKey otherUpk;
            otherUpk = pureCrypto.importPublicKey(record.getUpk());

            keys.add(otherUpk);
        }

        return keys;
    }

    /**
     *
     * @return current records version
     */
    public int getCurrentVersion() {
        return currentVersion;
    }

    /**
     *
     * @return PureStorage instance
     */
    public PureStorage getStorage() {
        return storage;
    }

    /**
     *
     * @return Backup public key
     */
    public VirgilPublicKey getBuppk() {
        return buppk;
    }

    /**
     *
     * @return Signing key pair
     */
    public VirgilKeyPair getOskp() {
        return oskp;
    }

    /**
     *
     * @return External public keys
     */
    public Map<String, List<VirgilPublicKey>> getExternalPublicKeys() {
        return externalPublicKeys;
    }
}
