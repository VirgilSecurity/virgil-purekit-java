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

import java.util.*;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Client;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Crypto;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.exception.ServiceErrorCode;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.utils.ValidateUtils;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

/**
 * PureStorage on Virgil cloud side
 */
public class VirgilCloudPureStorage implements PureStorage, PureModelSerializerDependent {

    @Override
    public PureModelSerializer getPureModelSerializer() {
        return pureModelSerializer;
    }

    @Override
    public void setPureModelSerializer(PureModelSerializer pureModelSerializer) {
        this.pureModelSerializer = pureModelSerializer;
    }

    private PureModelSerializer pureModelSerializer;
    private final HttpPureClient client;

    /**
     * Instantiates VirgilCloudPureStorage.
     *
     * @param signingKey Key used to sign data before sending to Virgil.
     */
    public VirgilCloudPureStorage(VirgilCrypto crypto,
                                  HttpPureClient client) {
        ValidateUtils.checkNull(crypto, "crypto");
        ValidateUtils.checkNull(client, "client");

        this.client = client;
    }

    /**
     * Insert a new user into a storage.
     *
     * @param userRecord User record.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws InvalidProtocolBufferException If provided UserRecord cannot be parsed as
     * Protobuf message.
     * @throws SigningException Please, see
     * {@link com.virgilsecurity.sdk.crypto.VirgilCrypto#generateSignature} method's doc.
     */
    @Override
    public void insertUser(UserRecord userRecord)
        throws ProtocolException, ProtocolHttpException, InvalidProtocolBufferException,
        SigningException {

        sendUser(userRecord, true);
    }

    /**
     * Updates a user in a storage.
     *
     * @param userRecord User record.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws InvalidProtocolBufferException If provided UserRecord cannot be parsed as
     * Protobuf message.
     * @throws SigningException Please, see
     * {@link com.virgilsecurity.sdk.crypto.VirgilCrypto#generateSignature} method's doc.
     */
    @Override
    public void updateUser(UserRecord userRecord)
        throws ProtocolException, ProtocolHttpException, InvalidProtocolBufferException,
        SigningException {

        sendUser(userRecord, false);
    }

    @Override
    public void updateUsers(Iterable<UserRecord> userRecords, int previousPheVersion) throws Exception {
        throw new UnsupportedOperationException(
                "This method always throws UnsupportedOperationException, as in case of using "
                        + "Virgil Cloud storage, rotation happens on the Virgil side."
        );
    }

    /**
     * Obtains a user record with the given userId from a storage.
     *
     * @param userId User Id.
     *
     * @return UserRecord.
     *
     * @throws PureLogicException If a user has not been found in a storage or user id mismatches
     * the one from a server. Use {@link PureLogicException#getErrorStatus()} to know the particular
     * case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws InvalidProtocolBufferException If a PurekitProtosV3Storage.UserRecord received from
     * a server cannot be parsed as a Protobuf message.
     * @throws VerificationException If signature verification operation failed.
     */
    @Override
    public UserRecord selectUser(String userId)
        throws PureLogicException, ProtocolException, ProtocolHttpException,
        InvalidProtocolBufferException, VerificationException {

        PurekitProtosV3Storage.UserRecord protobufRecord;

        try {
            protobufRecord = client.getUser(userId);
        } catch (ProtocolException exception) {
            if (exception.getErrorCode() == ServiceErrorCode.USER_NOT_FOUND.getCode()) {
                throw new PureLogicException(
                    PureLogicException.ErrorStatus.USER_NOT_FOUND_IN_STORAGE
                );
            }

            throw exception;
        } catch (ProtocolHttpException exception) {
            throw exception;
        }

        UserRecord userRecord = pureModelSerializer.parseUserRecord(protobufRecord);

        if (!userRecord.getUserId().equals(userId)) {
            throw new PureLogicException(PureLogicException.ErrorStatus.USER_ID_MISMATCH);
        }

        return userRecord;
    }

    /**
     * Obtains a users record with the given userId from a storage.
     *
     * @param userIds User Ids.
     *
     * @return UserRecords.
     *
     * @throws PureLogicException If user Id duplicate has been found or user id mismatches the one
     * from a server. Use {@link PureLogicException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws InvalidProtocolBufferException If a PurekitProtosV3Storage.UserRecord received from
     * a server cannot be parsed as a Protobuf message.
     * @throws VerificationException If signature verification operation failed.
     */
    @Override
    public Iterable<UserRecord> selectUsers(Set<String> userIds)
        throws PureLogicException, ProtocolException, ProtocolHttpException,
        InvalidProtocolBufferException, VerificationException {

        if (userIds.isEmpty()) {
            return Collections.emptyList();
        }

        HashSet<String> idsSet = new HashSet<>(userIds);

        PurekitProtosV3Storage.UserRecords protoRecords;

        protoRecords = client.getUsers(userIds);

        if (protoRecords.getUserRecordsCount() != userIds.size()) {
            throw new PureLogicException(PureLogicException.ErrorStatus.DUPLICATE_USER_ID);
        }

        ArrayList<UserRecord> userRecords = new ArrayList<>(protoRecords.getUserRecordsCount());

        for (PurekitProtosV3Storage.UserRecord protobufRecord : protoRecords.getUserRecordsList()) {
            UserRecord userRecord = pureModelSerializer.parseUserRecord(protobufRecord);

            if (!idsSet.contains(userRecord.getUserId())) {
                throw new PureLogicException(PureLogicException.ErrorStatus.USER_ID_MISMATCH);
            }

            idsSet.remove(userRecord.getUserId());

            userRecords.add(userRecord);
        }

        return userRecords;
    }

    /**
     * This method throws UnsupportedOperationException, as in case of using Virgil Cloud storage,
     * rotation happens on Virgil side.
     *
     * @param pheRecordVersion PHE record version.
     *
     * @return always throws UnsupportedOperationException.
     *
     * @throws UnsupportedOperationException always.
     */
    @Override
    public Iterable<UserRecord> selectUsers(int pheRecordVersion) {
        throw new UnsupportedOperationException(
            "This method always throws UnsupportedOperationException, as in case of using "
                + "Virgil Cloud storage, rotation happens on the Virgil side."
        );
    }

    /**
     * Deletes user with the given id.
     *
     * @param userId User Id.
     * @param cascade Deletes all user cell keys if true.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    @Override
    public void deleteUser(String userId, boolean cascade)
        throws ProtocolException, ProtocolHttpException {

        client.deleteUser(userId, cascade);
    }

    /**
     * Obtains CellKey for given userId and dataId from a storage.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @return CellKey.
     *
     * @throws PureLogicException If cell key has not been found or if storage signature
     * verification has been failed or user id mismatches the one from a server.
     * Use {@link PureLogicException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws VerificationException If signature verification operation failed.
     * @throws InvalidProtocolBufferException If a CellKey received from a server cannot be parsed
     * as a Protobuf message.
     */
    @Override
    public CellKey selectCellKey(String userId, String dataId)
        throws PureLogicException, ProtocolException, ProtocolHttpException, VerificationException,
        InvalidProtocolBufferException {

        PurekitProtosV3Storage.CellKey protobufRecord;
        try {
            protobufRecord = client.getCellKey(userId, dataId);
        } catch (ProtocolException exception) {
            if (exception.getErrorCode() == ServiceErrorCode.CELL_KEY_NOT_FOUND.getCode()) {
                return null;
            }

            throw exception;
        } catch (ProtocolHttpException exception) {
            throw exception;
        }

        CellKey cellKey = pureModelSerializer.parseCellKey(protobufRecord);

        if (!userId.equals(cellKey.getUserId()) || !dataId.equals(cellKey.getDataId())) {
            throw new PureLogicException(PureLogicException.ErrorStatus.KEY_ID_MISMATCH);
        }

        return cellKey;
    }

    /**
     * Insert CellKey key into a storage.
     *
     * @implSpec this method MUST throw {@link PureLogicException} with
     * {@link PureLogicException.ErrorStatus#CELL_KEY_ALREADY_EXISTS_IN_STORAGE} if key with given
     * userId and dataId already exists.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     * @param cellKey Cell key record.
     *
     * @throws PureLogicException If a cell key already exists in a storage.
     * Use {@link PureLogicException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws SigningException If crypto sign operation failed.
     */
    @Override
    public void insertCellKey(CellKey cellKey)
        throws PureLogicException, ProtocolException, ProtocolHttpException, SigningException {

        insertKey(cellKey, true);
    }

    /**
     * Updates CellKey.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     * @param cellKey Cell key record.
     *
     * @throws PureLogicException If a cell key already exists in a storage.
     * Use {@link PureLogicException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     * @throws SigningException If crypto sign operation failed.
     */
    @Override
    public void updateCellKey(CellKey cellKey)
        throws PureLogicException, ProtocolException, ProtocolHttpException, SigningException {

        insertKey(cellKey, false);
    }

    /**
     * Deletes cell key with given userId and dataId.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    @Override
    public void deleteCellKey(String userId, String dataId)
        throws ProtocolException, ProtocolHttpException {

        client.deleteCellKey(userId, dataId);
    }

    @Override
    public void insertRole(Role role) throws Exception {
        PurekitProtosV3Storage.Role protobufRecord = pureModelSerializer.serializeRole(role);

        client.insertRole(protobufRecord);
    }

    @Override
    public Iterable<Role> selectRoles(Set<String> roleNames) throws Exception {
        if (roleNames.isEmpty()) {
            return Collections.emptyList();
        }

        HashSet<String> namesSet = new HashSet<>(roleNames);

        PurekitProtosV3Storage.Roles protoRecords = client.getRoles(roleNames);

        if (protoRecords.getRolesCount() != roleNames.size()) {
            throw new PureLogicException(PureLogicException.ErrorStatus.DUPLICATE_ROLE_NAME);
        }

        ArrayList<Role> roles = new ArrayList<>(protoRecords.getRolesCount());

        for (PurekitProtosV3Storage.Role protobufRecord : protoRecords.getRolesList()) {
            Role role = pureModelSerializer.parseRole(protobufRecord);

            if (!namesSet.contains(role.getRoleName())) {
                throw new PureLogicException(PureLogicException.ErrorStatus.ROLE_NAME_MISMATCH);
            }

            namesSet.remove(role.getRoleName());

            roles.add(role);
        }

        return roles;
    }

    @Override
    public void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) throws Exception {
        PurekitProtosV3Storage.RoleAssignments.Builder protobufBuilder = PurekitProtosV3Storage.RoleAssignments.newBuilder();

        for (RoleAssignment roleAssignment: roleAssignments) {
            protobufBuilder.addRoleAssignments(pureModelSerializer.serializeRoleAssignment(roleAssignment));
        }

        PurekitProtosV3Storage.RoleAssignments protobufRecord = protobufBuilder.build();

        client.insertRoleAssignments(protobufRecord);
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) throws Exception {
        PurekitProtosV3Client.GetRoleAssignments request = PurekitProtosV3Client.GetRoleAssignments.newBuilder()
                .setUserId(userId)
                .build();

        PurekitProtosV3Storage.RoleAssignments protoRecords = client.getRoleAssignments(request);

        ArrayList<RoleAssignment> roleAssignments = new ArrayList<>(protoRecords.getRoleAssignmentsCount());

        for (PurekitProtosV3Storage.RoleAssignment protobufRecord : protoRecords.getRoleAssignmentsList()) {
            RoleAssignment roleAssignment = pureModelSerializer.parseRoleAssignment(protobufRecord);

            if (roleAssignment.getUserId().equals(userId)) {
                throw new PureLogicException(PureLogicException.ErrorStatus.USER_ID_MISMATCH);
            }

            roleAssignments.add(roleAssignment);
        }

        return roleAssignments;
    }

    @Override
    public RoleAssignment selectRoleAssignment(String roleName, String userId) throws Exception {
        PurekitProtosV3Client.GetRoleAssignment request = PurekitProtosV3Client.GetRoleAssignment.newBuilder()
                .setUserId(userId)
                .setRoleName(roleName)
                .build();

        PurekitProtosV3Storage.RoleAssignment protobufRecord = client.getRoleAssignment(request);

        return pureModelSerializer.parseRoleAssignment(protobufRecord);
    }

    @Override
    public void deleteRoleAssignments(String roleName, Set<String> userIds) throws Exception {
        if (userIds.isEmpty()) {
            return;
        }

        PurekitProtosV3Client.DeleteRoleAssignments request = PurekitProtosV3Client.DeleteRoleAssignments
                .newBuilder()
                .addAllUserIds(userIds)
                .setRoleName(roleName).
                build();

        client.deleteRoleAssignments(request);
    }

    private void sendUser(UserRecord userRecord, boolean isInsert)
        throws ProtocolException, ProtocolHttpException, InvalidProtocolBufferException,
        SigningException {

        PurekitProtosV3Storage.UserRecord protobufRecord = pureModelSerializer.serializeUserRecord(userRecord);

        if (isInsert) {
            client.insertUser(protobufRecord);
        } else {
            client.updateUser(userRecord.getUserId(), protobufRecord);
        }
    }

    private void insertKey(CellKey cellKey, boolean isInsert)
        throws PureLogicException, ProtocolException, ProtocolHttpException, SigningException {

        PurekitProtosV3Storage.CellKey protobufRecord = pureModelSerializer.serializeCellKey(cellKey);

        try {
            if (isInsert) {
                try {
                    client.insertCellKey(protobufRecord);
                } catch (ProtocolException exception) {
                    if (exception.getErrorCode()
                        == ServiceErrorCode.CELL_KEY_ALREADY_EXISTS.getCode()) {

                        throw new PureLogicException(
                            PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE
                        );
                    }

                    throw exception;
                }
            } else {
                client.updateCellKey(cellKey.getUserId(), cellKey.getDataId(), protobufRecord);
            }
        } catch (ProtocolException | ProtocolHttpException exception) {
            throw exception;
        }
    }
}
