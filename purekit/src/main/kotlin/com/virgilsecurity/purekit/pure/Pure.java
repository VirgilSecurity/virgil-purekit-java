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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.virgilsecurity.crypto.foundation.Base64;
import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.phe.PheCipher;
import com.virgilsecurity.crypto.phe.PheClient;
import com.virgilsecurity.crypto.phe.PheClientEnrollAccountResult;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Grant;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.utils.ValidateUtils;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import static com.virgilsecurity.crypto.foundation.FoundationException.ERROR_KEY_RECIPIENT_IS_NOT_FOUND;

/**
 * Main class for interactions with PureKit
 */
public class Pure {

    private final VirgilCrypto crypto;
    private final PureCrypto pureCrypto;
    private final PheCipher cipher;
    private final PureStorage storage;
    private final int currentVersion;
    private final PheClient currentClient;
    private final byte[] updateToken;
    private final PheClient previousClient;
    private final byte[] ak;
    private final VirgilPublicKey buppk;
    private final VirgilPublicKey hpk;
    private final VirgilKeyPair oskp;
    private final HttpPheClient httpPheClient;
    private final Map<String, List<VirgilPublicKey>> externalPublicKeys;

    private final static int currentGrantVersion = 1;

    /**
     * Instantiates Pure.
     *
     * @param context PureContext.
     */
    public Pure(PureContext context) throws PureCryptoException {
        try {
            this.crypto = context.getCrypto();
            this.pureCrypto = new PureCrypto(this.crypto);
            this.cipher = new PheCipher();
            this.cipher.setRandom(this.crypto.getRng());
            this.storage = context.getStorage();
            this.currentClient = new PheClient();
            this.currentClient.setOperationRandom(this.crypto.getRng());
            this.currentClient.setRandom(this.crypto.getRng());
            this.currentClient.setKeys(context.getAppSecretKey().getPayload(),
                    context.getServicePublicKey().getPayload());

            if (context.getUpdateToken() != null) {
                this.currentVersion = context.getServicePublicKey().getVersion() + 1;
                this.updateToken = context.getUpdateToken().getPayload();
                this.previousClient = new PheClient();
                this.previousClient.setOperationRandom(this.crypto.getRng());
                this.previousClient.setRandom(this.crypto.getRng());
                this.previousClient.setKeys(context.getAppSecretKey().getPayload(),
                        context.getServicePublicKey().getPayload());
                this.currentClient.rotateKeys(context.getUpdateToken().getPayload());
            } else {
                this.currentVersion = context.getServicePublicKey().getVersion();
                this.updateToken = null;
                this.previousClient = null;
            }

            this.ak = context.getAk().getPayload();
            this.buppk = context.getBuppk();
            this.hpk = context.getHpk();
            this.oskp = context.getOskp();
            this.httpPheClient = context.getPheClient();
            this.externalPublicKeys = context.getExternalPublicKeys();
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    /**
     * Register new user.
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
    public void registerUser(String userId, String password) throws Exception {

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
    public AuthResult authenticateUser(String userId, String password, String sessionId)
        throws Exception {

        try {
            ValidateUtils.checkNullOrEmpty(userId, "userId");
            ValidateUtils.checkNullOrEmpty(password, "password");

            byte[] phek = computePheKey(userId, password);

            byte[] uskData = cipher.decrypt(storage.selectUser(userId).getEncryptedUsk(), phek);

            VirgilKeyPair ukp = crypto.importPrivateKey(uskData);

            PureGrant grant = new PureGrant(ukp, userId, sessionId, new Date());

            int timestamp = (int) (grant.getCreationDate().getTime() / 1000);
            PurekitProtosV3Grant.EncryptedGrantHeader.Builder headerBuilder =
                    PurekitProtosV3Grant.EncryptedGrantHeader.newBuilder()
                            .setCreationDate(timestamp)
                            .setUserId(grant.getUserId());

            if (sessionId != null) {
                headerBuilder.setSessionId(sessionId);
            }

            PurekitProtosV3Grant.EncryptedGrantHeader header = headerBuilder.build();

            byte[] headerBytes = header.toByteArray();

            byte[] encryptedPhek = cipher.authEncrypt(phek, headerBytes, this.ak);

            PurekitProtosV3Grant.EncryptedGrant encryptedGrantData =
                    PurekitProtosV3Grant.EncryptedGrant.newBuilder()
                            .setVersion(Pure.currentGrantVersion)
                            .setHeader(ByteString.copyFrom(headerBytes))
                            .setEncryptedPhek(ByteString.copyFrom(encryptedPhek))
                            .build();

            String encryptedGrant = new String(Base64.encode(encryptedGrantData.toByteArray()));

            return new AuthResult(grant, encryptedGrant);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
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
    public AuthResult authenticateUser(String userId, String password) throws Exception {

        return authenticateUser(userId, password, null);
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
     * {@link VirgilCrypto#importPrivateKey}, {@link VirgilCrypto#verifySignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a PurekitProtosV3Storage.UserRecord received from
     * a server cannot be parsed as a Protobuf message.
     */
    public PureGrant createUserGrantAsAdmin(String userId, VirgilPrivateKey bupsk)
        throws Exception {

        ValidateUtils.checkNullOrEmpty(userId, "userId");

        UserRecord userRecord = storage.selectUser(userId);

        byte[] usk = crypto.decrypt(userRecord.getEncryptedUskBackup(), bupsk);

        VirgilKeyPair upk = crypto.importPrivateKey(usk);

        return new PureGrant(upk, userId, null, new Date());
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
    public PureGrant decryptGrantFromUser(String encryptedGrantString) throws Exception {

        try {
            ValidateUtils.checkNullOrEmpty(encryptedGrantString, "encryptedGrantString");

            byte[] encryptedGrantData = Base64.decode(encryptedGrantString.getBytes());

            PurekitProtosV3Grant.EncryptedGrant encryptedGrant =
                    PurekitProtosV3Grant.EncryptedGrant.parseFrom(encryptedGrantData);

            ByteString encryptedData = encryptedGrant.getEncryptedPhek();

            byte[] phek = cipher.authDecrypt(encryptedData.toByteArray(),
                    encryptedGrant.getHeader().toByteArray(),
                    this.ak);

            PurekitProtosV3Grant.EncryptedGrantHeader header =
                    PurekitProtosV3Grant.EncryptedGrantHeader.parseFrom(encryptedGrant.getHeader());

            UserRecord userRecord = storage.selectUser(header.getUserId());

            byte[] usk = cipher.decrypt(userRecord.getEncryptedUsk(), phek);

            VirgilKeyPair ukp = crypto.importPrivateKey(usk);

            String sessionId = header.getSessionId();

            if (sessionId.isEmpty()) {
                sessionId = null;
            }

            return new PureGrant(ukp,
                    header.getUserId(),
                    sessionId,
                    new Date((long) header.getCreationDate() * 1000));
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }



    /**
     * Changes user password. All encrypted data remains accessible after this method call.
     *
     * @param userId UserId.
     *
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
    public void changeUserPassword(String userId, String oldPassword, String newPassword)
        throws Exception {

        try {
            ValidateUtils.checkNullOrEmpty(userId, "userId");
            ValidateUtils.checkNullOrEmpty(oldPassword, "oldPassword");
            ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

            byte[] oldPhek = computePheKey(userId, oldPassword);
            UserRecord userRecord = storage.selectUser(userId);
            byte[] privateKeyData = cipher.decrypt(userRecord.getEncryptedUsk(), oldPhek);

            changeUserPassword(userRecord, privateKeyData, newPassword);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
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
    public void changeUserPassword(PureGrant grant, String newPassword) throws Exception {

        ValidateUtils.checkNull(grant, "grant");

        ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

        UserRecord userRecord = storage.selectUser(grant.getUserId());

        byte[] privateKeyData = crypto.exportPrivateKey(grant.getUkp().getPrivateKey());

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
    public void resetUserPassword(String userId, String newPassword) throws Exception {
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
    public void deleteUser(String userId, boolean cascade) throws Exception {

        storage.deleteUser(userId, cascade);
        // TODO: Should delete role assignments
    }

    /**
     * Performs PHE records rotation for all users with old phe version.
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
    public long performRotation() throws Exception {

        ValidateUtils.checkNull(this.updateToken, "updateToken");

        if (this.currentVersion <= 1) {
            return 0;
        }

        long rotations = 0;

        PheClient pheClient = getClient(this.currentVersion - 1);

        while (true) {
            Iterable<UserRecord> userRecords = storage.selectUsers(this.currentVersion - 1);
            ArrayList<UserRecord> newUserRecords = new ArrayList<>();

            for (UserRecord userRecord: userRecords) {
                assert userRecord.getPheRecordVersion() == this.currentVersion - 1;

                byte[] newRecord = pheClient.updateEnrollmentRecord(userRecord.getPheRecord(),
                                                                    this.updateToken);

                UserRecord newUserRecord = new UserRecord(
                    userRecord.getUserId(),
                    newRecord,
                    this.currentVersion,
                    userRecord.getUpk(),
                    userRecord.getEncryptedUsk(),
                    userRecord.getEncryptedUskBackup(),
                    userRecord.getEncryptedPwdHash()
                );

                newUserRecords.add(newUserRecord);
            }

            storage.updateUsers(newUserRecords, this.currentVersion - 1);

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
     * @throws PureLogicException Please, see {@link PureStorage#selectKey},
     * {@link PureStorage#selectUsers}, {@link PureStorage#insertKey} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#generateKeyPair},
     * {@link VirgilCrypto#importPublicKey}, {@link VirgilCrypto#exportPublicKey},
     * {@link VirgilCrypto#exportPrivateKey}, {@link VirgilCrypto#encrypt}
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
     */
    public byte[] encrypt(String userId, String dataId, byte[] plainText) throws Exception {

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
     * @throws PureLogicException Please, see {@link PureStorage#selectKey},
     * {@link PureStorage#selectUsers}, {@link PureStorage#insertKey} methods' PureLogicException doc.
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
                          byte[] plainText)
        throws Exception {

        ValidateUtils.checkNull(otherUserIds, "otherUserIds");
        ValidateUtils.checkNull(publicKeys, "publicKeys");
        ValidateUtils.checkNull(plainText, "plainText");

        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        VirgilPublicKey cpk;

        // Key already exists
        CellKey cellKey1 = storage.selectKey(userId, dataId);

        if (cellKey1 == null) {
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
                    VirgilPublicKey otherUpk = crypto.importPublicKey(record.getUpk());
                    recipientList.add(otherUpk);
                }

                Iterable<Role> roles = storage.selectRoles(roleNames);

                for (Role role: roles) {
                    VirgilPublicKey rpk = crypto.importPublicKey(role.getRpk());
                    recipientList.add(rpk);
                }

                List<VirgilPublicKey> externalPublicKeys = this.externalPublicKeys.get(dataId);

                if (externalPublicKeys != null) {
                    recipientList.addAll(externalPublicKeys);
                }

                VirgilKeyPair ckp = crypto.generateKeyPair();
                byte[] cpkData = crypto.exportPublicKey(ckp.getPublicKey());
                byte[] cskData = crypto.exportPrivateKey(ckp.getPrivateKey());

                PureCryptoData encryptedCskData = pureCrypto.encrypt(cskData, oskp.getPrivateKey(), recipientList);

                storage.insertKey(userId,
                                  dataId,
                                  new CellKey(cpkData,
                                              encryptedCskData.getCms(),
                                              encryptedCskData.getBody()));
                cpk = ckp.getPublicKey();
            } catch (PureLogicException exception) {
                if (exception.getErrorStatus()
                    != PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE) {

                    throw exception;
                }

                CellKey cellKey2 = storage.selectKey(userId, dataId);

                cpk = crypto.importPublicKey(cellKey2.getCpk());
            }
        } else {
            cpk = crypto.importPublicKey(cellKey1.getCpk());
        }

        // TODO: Replace crypto.encrypt everywhere
        return crypto.encrypt(plainText, Collections.singletonList(cpk));
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
     * {@link PureStorage#selectKey(String, String)} method's PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPrivateKey},
     * {@link VirgilCrypto#decrypt}, {@link VirgilCrypto#verifySignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
     */
    public byte[] decrypt(PureGrant grant, String ownerUserId, String dataId, byte[] cipherText)
        throws Exception {

        ValidateUtils.checkNull(grant, "grant");
        ValidateUtils.checkNull(cipherText, "cipherText");

        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        String userId = ownerUserId;

        if (userId == null) {
            userId = grant.getUserId();
        }

        CellKey cellKey = storage.selectKey(userId, dataId);

        if (cellKey == null) {
            throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_NOT_FOUND_IN_STORAGE);
        }

        PureCryptoData pureCryptoData = new PureCryptoData(cellKey.getEncryptedCskCms(),
                cellKey.getEncryptedCskBody());

        byte[] csk = null;

        try {
            csk = pureCrypto.decrypt(pureCryptoData, oskp.getPublicKey(), grant.getUkp().getPrivateKey());
        }
        catch (PureCryptoException e) {
            if (e.getFoundationException() == null || e.getFoundationException().getStatusCode() != ERROR_KEY_RECIPIENT_IS_NOT_FOUND) {
                throw e;
            }

            Iterable<RoleAssignment> roleAssignments = storage.selectRoleAssignments(grant.getUserId());

            // TODO: Replace ByteBuffer
            Set<ByteBuffer> publicKeysIds = pureCrypto.extractPublicKeysIds(cellKey.getEncryptedCskCms());

            for (RoleAssignment roleAssignment: roleAssignments) {
                ByteBuffer publicKeyId = ByteBuffer.wrap(roleAssignment.getPublicKeyId());

                if (publicKeysIds.contains(publicKeyId)) {
                    // FIXME: Refactor
                    byte[] rskData = crypto.decrypt(roleAssignment.getEncryptedRsk(), grant.getUkp().getPrivateKey());

                    VirgilKeyPair rkp = crypto.importPrivateKey(rskData);

                    csk = pureCrypto.decrypt(pureCryptoData, oskp.getPublicKey(), rkp.getPrivateKey());
                    break;
                }
            }

            if (csk == null) {
                throw new PureLogicException(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA);
            }
        }

        VirgilKeyPair ckp = crypto.importPrivateKey(csk);

        return crypto.decrypt(cipherText, ckp.getPrivateKey());
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
     * {@link PureStorage#selectKey(String, String)} method's PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPrivateKey},
     * {@link VirgilCrypto#decrypt}, {@link VirgilCrypto#verifySignature} methods'
     * CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
     */
    public byte[] decrypt(VirgilPrivateKey privateKey,
                           String ownerUserId,
                           String dataId,
                           byte[] cipherText)
            throws Exception {

        // TODO: Delete copy&paste

        ValidateUtils.checkNull(privateKey, "privateKey");

        ValidateUtils.checkNullOrEmpty(dataId, "dataId");
        ValidateUtils.checkNullOrEmpty(ownerUserId, "ownerUserId");

        CellKey cellKey = storage.selectKey(ownerUserId, dataId);

        if (cellKey == null) {
            throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_NOT_FOUND_IN_STORAGE);
        }

        PureCryptoData pureCryptoData = new PureCryptoData(cellKey.getEncryptedCskCms(),
                cellKey.getEncryptedCskBody());

        byte[] csk = pureCrypto.decrypt(pureCryptoData, oskp.getPublicKey(), privateKey);

        VirgilKeyPair ckp = crypto.importPrivateKey(csk);

        return crypto.decrypt(cipherText, ckp.getPrivateKey());
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
     * @throws PureLogicException Please, see {@link PureStorage#selectKey},
     * {@link PureStorage#updateKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPublicKey},
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
     */
    public void share(PureGrant grant, String dataId, String otherUserId) throws Exception {

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
     * @throws PureLogicException Please, see {@link PureStorage#selectKey},
     * {@link PureStorage#updateKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
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
                      Collection<VirgilPublicKey> publicKeys)
        throws Exception {

        ValidateUtils.checkNull(grant, "grant");
        ValidateUtils.checkNull(otherUserIds, "otherUserIds");
        ValidateUtils.checkNull(publicKeys, "publicKeys");

        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        ArrayList<VirgilPublicKey> keys = keysWithOthers(publicKeys, otherUserIds);
        CellKey cellKey = storage.selectKey(grant.getUserId(), dataId);

        byte[] encryptedCskCms = pureCrypto.addRecipients(cellKey.getEncryptedCskCms(),
                                                          grant.getUkp().getPrivateKey(),
                                                          keys);

        CellKey cellKeyNew = new CellKey(cellKey.getCpk(),
                                         encryptedCskCms,
                                         cellKey.getEncryptedCskBody());

        storage.updateKey(grant.getUserId(), dataId, cellKeyNew);
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
     * @throws PureLogicException Please, see {@link PureStorage#selectKey},
     * {@link PureStorage#updateKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
     * @throws CryptoException Please, see {@link VirgilCrypto#importPublicKey},
     * {@link VirgilCrypto#verifySignature} methods' CryptoException doc.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
     */
    public void unshare(String ownerUserId, String dataId, String otherUserId) throws Exception {

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
     * @throws PureLogicException Please, see {@link PureStorage#selectKey},
     * {@link PureStorage#updateKey}, {@link PureStorage#selectUsers} methods' PureLogicException doc.
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
                        Collection<VirgilPublicKey> publicKeys)
        throws Exception {

        ValidateUtils.checkNull(otherUserIds, "otherUserIds");
        ValidateUtils.checkNull(publicKeys, "publicKeys");

        ValidateUtils.checkNullOrEmpty(ownerUserId, "ownerUserId");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        ArrayList<VirgilPublicKey> keys = keysWithOthers(publicKeys, otherUserIds);

        CellKey cellKey = storage.selectKey(ownerUserId, dataId);

        byte[] encryptedCskCms = pureCrypto.deleteRecipients(cellKey.getEncryptedCskCms(), keys);

        CellKey cellKeyNew = new CellKey(cellKey.getCpk(),
                                         encryptedCskCms,
                                         cellKey.getEncryptedCskBody());

        storage.updateKey(ownerUserId, dataId, cellKeyNew);
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
    public void deleteKey(String userId, String dataId) throws Exception {

        storage.deleteKey(userId, dataId);
    }

    public void createRole(String roleName, Set<String> userIds) throws Exception {
        VirgilKeyPair rkp = crypto.generateKeyPair();
        byte[] rpkData = crypto.exportPublicKey(rkp.getPublicKey());
        byte[] rskData = crypto.exportPrivateKey(rkp.getPrivateKey());

        Role role = new Role(roleName, rpkData);

        storage.insertRole(role);

        assignRole(roleName, rkp.getPublicKey().getIdentifier(), rskData, userIds);
    }

    public void assignRole(String roleToAssign, PureGrant grant, Set<String> userIds) throws Exception {
        RoleAssignment roleAssignment = storage.selectRoleAssignment(roleToAssign, grant.getUserId());

        byte[] rskData = crypto.decrypt(roleAssignment.getEncryptedRsk(), grant.getUkp().getPrivateKey());

        assignRole(roleToAssign, roleAssignment.getPublicKeyId(), rskData, userIds);
    }

    private void assignRole(String roleName, byte[] publicKeyId, byte[] rskData, Set<String> userIds) throws Exception {
        Iterable<UserRecord> userRecords = storage.selectUsers(userIds);

        ArrayList<RoleAssignment> roleAssignments = new ArrayList<>(userIds.size());

        for (UserRecord userRecord: userRecords) {
            VirgilPublicKey upk = crypto.importPublicKey(userRecord.getUpk());

            byte[] encryptedRsk = crypto.encrypt(rskData, upk);

            roleAssignments.add(new RoleAssignment(roleName, userRecord.getUserId(), publicKeyId, encryptedRsk));
        }

        storage.insertRoleAssignments(roleAssignments);
    }

    public void deassignRole(String roleName, Set<String> userIds) throws Exception {
        storage.deleteRoleAssignments(roleName, userIds);
    }

    private void registerUser(String userId, String password, boolean isUserNew) throws Exception {

        try {
            ValidateUtils.checkNullOrEmpty(userId, "userId");
            ValidateUtils.checkNullOrEmpty(password, "password");

            PurekitProtos.EnrollmentRequest request = PurekitProtos.EnrollmentRequest
                    .newBuilder()
                    .setVersion(this.currentVersion)
                    .build();
            PurekitProtos.EnrollmentResponse response = httpPheClient.enrollAccount(request);

            byte[] passwordHash = crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

            byte[] encryptedPwdHash = crypto.encrypt(passwordHash, Collections.singletonList(this.hpk));

            PheClientEnrollAccountResult result = currentClient.enrollAccount(
                    response.getResponse().toByteArray(),
                    passwordHash
            );

            VirgilKeyPair ukp = crypto.generateKeyPair();

            byte[] uskData = crypto.exportPrivateKey(ukp.getPrivateKey());

            byte[] encryptedUsk = cipher.encrypt(uskData, result.getAccountKey());

            byte[] encryptedUskBackup = crypto.encrypt(uskData, Collections.singletonList(this.buppk));

            byte[] publicKey = crypto.exportPublicKey(ukp.getPublicKey());

            UserRecord userRecord = new UserRecord(
                userId,
                result.getEnrollmentRecord(),
                this.currentVersion,
                publicKey,
                encryptedUsk,
                encryptedUskBackup,
                encryptedPwdHash
            );

            if (isUserNew) {
                storage.insertUser(userRecord);
            } else {
                storage.updateUser(userRecord);
            }
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    private PheClient getClient(int pheVersion) throws NullPointerException {
        if (this.currentVersion == pheVersion) {
            return this.currentClient;
        } else if (this.currentVersion == pheVersion + 1) {
            return this.previousClient;
        } else {
            throw new NullPointerException("client");
        }
    }

    private void changeUserPassword(UserRecord userRecord,
                                    byte[] privateKeyData,
                                    String newPassword)
        throws Exception {

        try {
            ValidateUtils.checkNullOrEmpty(newPassword, "newPassword");

            byte[] newPasswordHash = crypto.computeHash(newPassword.getBytes(),
                    HashAlgorithm.SHA512);

            PurekitProtos.EnrollmentRequest enrollRequest = PurekitProtos.EnrollmentRequest
                    .newBuilder()
                    .setVersion(this.currentVersion)
                    .build();
            PurekitProtos.EnrollmentResponse enrollResponse =
                httpPheClient.enrollAccount(enrollRequest);

            PheClientEnrollAccountResult enrollResult =
                    currentClient.enrollAccount(enrollResponse.getResponse().toByteArray(),
                            newPasswordHash);

            byte[] newEncryptedUsk = cipher.encrypt(privateKeyData, enrollResult.getAccountKey());

            byte[] encryptedPwdHash = crypto.encrypt(newPasswordHash,
                    Collections.singletonList(this.hpk));

            UserRecord newUserRecord = new UserRecord(
                userRecord.getUserId(),
                enrollResult.getEnrollmentRecord(),
                this.currentVersion,
                userRecord.getUpk(),
                newEncryptedUsk,
                userRecord.getEncryptedUskBackup(),
                encryptedPwdHash
            );

            storage.updateUser(newUserRecord);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    private ArrayList<VirgilPublicKey> keysWithOthers(Collection<VirgilPublicKey> publicKeys,
                                                      Set<String> otherUserIds)
        throws Exception {

        ArrayList<VirgilPublicKey> keys = new ArrayList<>(publicKeys);

        Iterable<UserRecord> otherUserRecords = storage.selectUsers(otherUserIds);

        for (UserRecord record : otherUserRecords) {
            VirgilPublicKey otherUpk;
            otherUpk = crypto.importPublicKey(record.getUpk());

            keys.add(otherUpk);
        }

        return keys;
    }

    private byte[] computePheKey(String userId, String password) throws Exception {

        try {
            byte[] passwordHash = crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);

            UserRecord userRecord = storage.selectUser(userId);

            PheClient client = getClient(userRecord.getPheRecordVersion());

            byte[] pheVerifyRequest = client.createVerifyPasswordRequest(passwordHash,
                    userRecord.getPheRecord());

            PurekitProtos.VerifyPasswordRequest request = PurekitProtos.VerifyPasswordRequest
                    .newBuilder()
                    .setVersion(userRecord.getPheRecordVersion())
                    .setRequest(ByteString.copyFrom(pheVerifyRequest))
                    .build();

            PurekitProtos.VerifyPasswordResponse response = httpPheClient.verifyPassword(request);

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

    public VirgilCrypto getCrypto() {
        return crypto;
    }

    public PureStorage getStorage() {
        return storage;
    }

    public int getCurrentVersion() {
        return currentVersion;
    }

    public byte[] getUpdateToken() {
        return updateToken;
    }

    public byte[] getAk() {
        return ak;
    }

    public VirgilPublicKey getBuppk() {
        return buppk;
    }

    public VirgilPublicKey getHpk() {
        return hpk;
    }

    public VirgilKeyPair getOskp() {
        return oskp;
    }

    public Map<String, List<VirgilPublicKey>> getExternalPublicKeys() {
        return externalPublicKeys;
    }
}
