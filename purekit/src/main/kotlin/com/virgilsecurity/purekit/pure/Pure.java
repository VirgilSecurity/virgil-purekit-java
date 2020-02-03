/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Grant;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.storage.PureStorageCellKeyNotFoundException;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.storage.PureStorageGenericException;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.pure.storage.PureStorage;
import com.virgilsecurity.purekit.utils.ValidateUtils;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * Main class for interactions with PureKit
 */
public class Pure {
    public static final long DEFAULT_GRANT_TTL = 60 * 60; // 1 hour
    private final int currentVersion;
    private final PureCrypto pureCrypto;
    private final PureStorage storage;
    private final byte[] ak;
    private final VirgilPublicKey buppk;
    private final VirgilKeyPair oskp;
    private final Map<String, List<VirgilPublicKey>> externalPublicKeys;
    private final PheManager pheManager;
    private final KmsManager kmsManager;

    private final static int currentGrantVersion = 1;

    /**
     * Instantiates Pure.
     *
     * @param context PureContext.
     */
    public Pure(PureContext context) throws PureCryptoException {
        this.pureCrypto = new PureCrypto(context.getCrypto());
        this.storage = context.getStorage();
        this.ak = context.getNonrotatableSecrets().getAk();
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws CryptoException Please, see {@link VirgilCrypto#encrypt},
     * {@link VirgilCrypto#generateKeyPair}, {@link VirgilCrypto#exportPrivateKey},
     * {@link VirgilCrypto#exportPublicKey}, {@link VirgilCrypto#generateSignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If provided UserRecord cannot be parsed as
     * Protobuf message.
     */
    public void registerUser(String userId, String password) throws PureException {

        registerUser(userId, password, true);
    }

    /**
     * Authenticates user.
     *
     * @param userId User Id.
     * @param password Password.
     * @param sessionId Optional sessionId which will be present in PureGrant.
     *
     * @return AuthResult with PureGrant and encrypted PureGrant.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException If provided password is invalid or - please, see
     * {@link PureStorage#selectUser(String)} PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPrivateKey},
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If a PurekitProtosV3Storage.UserRecord received from
     * a server cannot be parsed as a Protobuf message.
     */
    public AuthResult authenticateUser(String userId, String password, String sessionId, long ttl) throws PureException {

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(password, "password");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] phek = pheManager.computePheKey(userRecord, password);

        byte[] uskData = pureCrypto.decryptSymmetricNewNonce(userRecord.getEncryptedUsk(), new byte[0], phek);

        VirgilKeyPair ukp = pureCrypto.importPrivateKey(uskData);

        Date creationDate = new Date();
        Date expirationDate = new Date(creationDate.getTime() + ttl * 1000);

        PureGrant grant = new PureGrant(ukp, userId, sessionId, creationDate, expirationDate);

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

        byte[] encryptedGrantKey = pureCrypto.encryptSymmetricNewNonce(grantKeyRaw, new byte[0], ak);

        GrantKey grantKey = new GrantKey(userId, keyId, encryptedGrantKey, creationDate, expirationDate);

        storage.insertGrantKey(grantKey);

        byte[] encryptedPhek = pureCrypto.encryptSymmetricOneTimeKey(phek, headerBytes, grantKeyRaw);

        PurekitProtosV3Grant.EncryptedGrant encryptedGrantData =
                PurekitProtosV3Grant.EncryptedGrant.newBuilder()
                        .setVersion(Pure.currentGrantVersion)
                        .setHeader(ByteString.copyFrom(headerBytes))
                        .setEncryptedPhek(ByteString.copyFrom(encryptedPhek))
                        .build();

        String encryptedGrant = Base64.encode(encryptedGrantData.toByteArray());

        return new AuthResult(grant, encryptedGrant);
    }

    /**
     * Authenticates user.
     *
     * @param userId User Id.
     * @param password Password.
     *
     * @return AuthResult with PureGrant and encrypted PureGrant.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException If provided password is invalid or - please, see
     * {@link PureStorage#selectUser(String)} PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPrivateKey},
     * method's CryptoException doc.
     * @throws InvalidProtocolBufferException If a PurekitProtosV3Storage.UserRecord received from
     * a server cannot be parsed as a Protobuf message.
     */
    public AuthResult authenticateUser(String userId, String password, long ttl) throws PureException {

        return authenticateUser(userId, password, null, ttl);
    }

    public AuthResult authenticateUser(String userId, String password) throws PureException {

        return authenticateUser(userId, password, null, DEFAULT_GRANT_TTL);
    }

    public AuthResult authenticateUser(String userId, String password, String sessionId) throws PureException {

        return authenticateUser(userId, password, sessionId, DEFAULT_GRANT_TTL);
    }

    /**
     * Creates PureGrant for some user using admin backup private key.
     *
     * @param userId User Id.
     * @param bupsk Admin backup private key.
     *
     * @return PureGrant.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectUser(String)} PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#decrypt},
     * {@link VirgilCrypto#importPrivateKey}, {@link VirgilCrypto#veriffySignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a PurekitProtosV3Storage.UserRecord received from
     * a server cannot be parsed as a Protobuf message.
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

    public PureGrant createUserGrantAsAdmin(String userId, VirgilPrivateKey bupsk) throws PureException {
        return createUserGrantAsAdmin(userId, bupsk, DEFAULT_GRANT_TTL);
    }

    /**
     * Decrypt encrypted PureGrant that was stored on client-side.
     *
     * @param encryptedGrantString Encrypted PureGrant obtained from authenticateUser method.
     *
     * @return PureGrant.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectUser(String)} PureLogicException doc.
     * @throws InvalidProtocolBufferException If provided encryptedGrantString cannot be parsed as
     * protobuf message or a PurekitProtosV3Storage.UserRecord received from a server cannot be
     * parsed as a Protobuf message..
     * @throws CryptoException Please, see {@link VirgilCrypto#importPrivateKey},
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     */
    public PureGrant decryptGrantFromUser(String encryptedGrantString) throws PureException {

        ValidateUtils.checkNullOrEmpty(encryptedGrantString, "encryptedGrantString");

        byte[] encryptedGrantData = Base64.decode(encryptedGrantString.getBytes());

        PurekitProtosV3Grant.EncryptedGrant encryptedGrant;
        try {
            encryptedGrant = PurekitProtosV3Grant.EncryptedGrant.parseFrom(encryptedGrantData);
        } catch (InvalidProtocolBufferException e) {
            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_INVALID_PROTOBUF);
        }

        ByteString encryptedData = encryptedGrant.getEncryptedPhek();

        PurekitProtosV3Grant.EncryptedGrantHeader header;
        try {
            header = PurekitProtosV3Grant.EncryptedGrantHeader.parseFrom(encryptedGrant.getHeader());
        } catch (InvalidProtocolBufferException e) {
            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_INVALID_PROTOBUF);
        }

        GrantKey grantKey = storage.selectGrantKey(header.getUserId(), header.getKeyId().toByteArray());

        if (grantKey.getExpirationDate().before(new Date())) {
            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_IS_EXPIRED);
        }

        byte[] grantKeyRaw = pureCrypto.decryptSymmetricNewNonce(grantKey.getEncryptedGrantKey(), new byte[0], ak);

        byte[] phek = pureCrypto.decryptSymmetricOneTimeKey(encryptedData.toByteArray(),
                encryptedGrant.getHeader().toByteArray(),
                grantKeyRaw);

        UserRecord userRecord = storage.selectUser(header.getUserId());

        byte[] usk = pureCrypto.decryptSymmetricNewNonce(userRecord.getEncryptedUsk(), new byte[0], phek);

        VirgilKeyPair ukp = pureCrypto.importPrivateKey(usk);

        String sessionId = header.getSessionId();

        if (sessionId.isEmpty()) {
            sessionId = null;
        }

        return new PureGrant(ukp,
                header.getUserId(),
                sessionId,
                new Date((long) (header.getCreationDate()) * 1000),
                new Date((long) (header.getExpirationDate()) * 1000));
    }

    /**
     * Changes user password. All encrypted data remains accessible after this method call.
     *
     * @param userId UserId.
     * @param oldPassword Old password.
     * @param newPassword New password.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectUser(String)} PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#encrypt},
     * {@link VirgilCrypto#generateSignature}, {@link VirgilCrypto#verifySignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If provided UserRecord cannot be parsed as
     * Protobuf message or a PurekitProtosV3Storage.UserRecord received from a server cannot be
     * parsed as a Protobuf message..
     */
    public void changeUserPassword(String userId, String oldPassword, String newPassword) throws PureException {

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(oldPassword, "oldPassword");
        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] oldPhek = pheManager.computePheKey(userRecord, oldPassword);

        byte[] privateKeyData = pureCrypto.decryptSymmetricNewNonce(userRecord.getEncryptedUsk(), new byte[0], oldPhek);

        changeUserPassword(userRecord, privateKeyData, newPassword);
    }

    /**
     * Changes user password. All encrypted data remains accessible after this method call.
     *
     * @param grant PureGrant obtained either using {@link Pure#authenticateUser} or
     *              {@link Pure#createUserGrantAsAdmin}.
     * @param newPassword New password.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectUser(String)} PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#exportPrivateKey},
     * {@link VirgilCrypto#encrypt}, {@link VirgilCrypto#generateSignature},
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If provided UserRecord cannot be parsed as
     * Protobuf message or a PurekitProtosV3Storage.UserRecord received from a server cannot be
     * parsed as a Protobuf message.
     */
    public void changeUserPassword(PureGrant grant, String newPassword) throws PureException {

        ValidateUtils.checkNull(grant, "grant");
        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        UserRecord userRecord = storage.selectUser(grant.getUserId());

        byte[] privateKeyData = pureCrypto.exportPrivateKey(grant.getUkp().getPrivateKey());

        changeUserPassword(userRecord, privateKeyData, newPassword);
    }

    /**
     * Recovers user in case he doesn't remember his password
     *
     * Note: this method is under server-side rate-limiting, which prevents adversary from decrypting database.
     *
     * @param userId userId
     * @param newPassword new password
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectUser(String)} PureLogicException doc.
     */
    public void recoverUser(String userId, String newPassword) throws PureException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] pwdHash = kmsManager.recoverPwd(userRecord);

        byte[] oldPhek = pheManager.computePheKey(userRecord, pwdHash);

        byte[] privateKeyData = pureCrypto.decryptSymmetricNewNonce(userRecord.getEncryptedUsk(), new byte[0], oldPhek);

        changeUserPassword(userRecord, privateKeyData, newPassword);
    }

    /**
     * Resets user password, all encrypted user data becomes inaccessible.
     *
     * @param userId User id.
     * @param newPassword New password.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws CryptoException Please, see {@link VirgilCrypto#encrypt},
     * {@link VirgilCrypto#generateKeyPair}, {@link VirgilCrypto#exportPrivateKey},
     * {@link VirgilCrypto#exportPublicKey}, {@link VirgilCrypto#generateSignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If provided UserRecord cannot be parsed as
     * Protobuf message.
     */
    public void resetUserPassword(String userId, String newPassword) throws PureException {
        // TODO: Add possibility to delete cell keys? -> ????
        registerUser(userId, newPassword, false);
    }

    /**
     * Deletes user with given id.
     *
     * @param userId User Id.
     * @param cascade Deletes all user cell keys if true.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void deleteUser(String userId, boolean cascade) throws PureException {

        storage.deleteUser(userId, cascade);
        // TODO: Should delete role assignments
    }

    /**
     * Performs PHE and KMS records rotation for all users with old version.
     * Pure should be initialized with UpdateToken for this operation.
     *
     * @return Number of rotated records.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws InvalidProtocolBufferException If provided UserRecord cannot be parsed as
     * Protobuf message.
     * @throws com.virgilsecurity.sdk.crypto.exceptions.SigningException Please, see
     * {@link com.virgilsecurity.sdk.crypto.VirgilCrypto#generateSignature} method's doc.
     */
    public long performRotation() throws PureException {
        if (currentVersion <= 1) {
            return 0;
        }

        long rotations = 0;

        while (true) {
            Iterable<UserRecord> userRecords = storage.selectUsers(currentVersion - 1);
            ArrayList<UserRecord> newUserRecords = new ArrayList<>();

            for (UserRecord userRecord: userRecords) {
                assert userRecord.getRecordVersion() == currentVersion - 1;

                byte[] newRecord = pheManager.performRotation(userRecord.getPheRecord());
                byte[] newWrap = kmsManager.performRotation(userRecord.getPasswordRecoveryWrap());

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
                rotations += newUserRecords.size();
            }
        }

        return rotations;
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectCellKey},
     * {@link PureStorage#selectUsers}, {@link PureStorage#insertCellKey} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#generateKeyPair},
     * {@link VirgilCrypto#importPublicKey}, {@link VirgilCrypto#exportPublicKey},
     * {@link VirgilCrypto#exportPrivateKey}, {@link VirgilCrypto#encrypt}
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectCellKey},
     * {@link PureStorage#selectUsers}, {@link PureStorage#insertCellKey} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#generateKeyPair},
     * {@link VirgilCrypto#importPublicKey}, {@link VirgilCrypto#exportPublicKey},
     * {@link VirgilCrypto#exportPrivateKey}, {@link VirgilCrypto#encrypt},
     * {@link VirgilCrypto#verifySignature}, {@link VirgilCrypto#generateSignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message or a PurekitProtosV3Storage.UserRecord received from
     * a server cannot be parsed as a Protobuf message.
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
            } catch (PureStorageGenericException exception) {
                if (exception.getErrorStatus()
                    != PureStorageGenericException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE) {

                    throw exception;
                }

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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException If cell key has not been found in a storage, or please see
     * {@link PureStorage#selectCellKey(String, String)} method's PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPrivateKey},
     * {@link VirgilCrypto#decrypt}, {@link VirgilCrypto#verifySignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException If cell key has not been found in a storage, or please see
     * {@link PureStorage#selectCellKey(String, String)} method's PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPrivateKey},
     * {@link VirgilCrypto#decrypt}, {@link VirgilCrypto#verifySignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectCellKey},
     * {@link PureStorage#updateCellKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPublicKey},
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectCellKey},
     * {@link PureStorage#updateCellKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPublicKey},
     * {@link VirgilCrypto#verifySignature}, {@link VirgilCrypto#generateSignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message or a PurekitProtosV3Storage.UserRecord received from a server cannot
     * be parsed as a Protobuf message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectCellKey},
     * {@link PureStorage#updateCellKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPublicKey},
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws PureLogicException Please, see {@link PureStorage#selectCellKey},
     * {@link PureStorage#updateCellKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPublicKey},
     * {@link VirgilCrypto#verifySignature}, {@link VirgilCrypto#generateSignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message or a PurekitProtosV3Storage.UserRecord received from a server cannot
     * be parsed as a Protobuf message
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
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
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void unassignRole(String roleName, Set<String> userIds) throws PureException {
        storage.deleteRoleAssignments(roleName, userIds);
    }

    private void registerUser(String userId, String password, boolean isUserNew) throws PureException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(password, "password");

        byte[] passwordHash = pureCrypto.computePasswordHash(password);

        byte[] encryptedPwdHash = pureCrypto.encryptForBackup(passwordHash, buppk, oskp.getPrivateKey());

        KmsManager.PwdRecoveryData pwdRecoveryData = kmsManager.generatePwdRecoveryData(passwordHash);

        PheClientEnrollAccountResult pheResult = pheManager.getEnrollment(passwordHash);

        VirgilKeyPair ukp = pureCrypto.generateUserKey();

        byte[] uskData = pureCrypto.exportPrivateKey(ukp.getPrivateKey());

        byte[] encryptedUsk = pureCrypto.encryptSymmetricNewNonce(uskData, new byte[0], pheResult.getAccountKey());

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
    }

    private void changeUserPassword(UserRecord userRecord,
                                    byte[] privateKeyData,
                                    String newPassword) throws PureException {

        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        byte[] newPasswordHash = pureCrypto.computePasswordHash(newPassword);

        PheClientEnrollAccountResult enrollResult = pheManager.getEnrollment(newPasswordHash);

        KmsManager.PwdRecoveryData pwdRecoveryData = kmsManager.generatePwdRecoveryData(newPasswordHash);

        byte[] newEncryptedUsk = pureCrypto.encryptSymmetricNewNonce(privateKeyData, new byte[0], enrollResult.getAccountKey());

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
     * @return Auth key
     */
    public byte[] getAk() {
        return ak;
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
