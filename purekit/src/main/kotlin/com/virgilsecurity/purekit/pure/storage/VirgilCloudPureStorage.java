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

package com.virgilsecurity.purekit.pure.storage;

import java.util.*;

import com.google.protobuf.ByteString;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Client;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.pure.client.HttpPureClient;
import com.virgilsecurity.purekit.pure.client.ServiceErrorCode;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.utils.ValidateUtils;

/**
 * PureStorage on Virgil cloud side
 */
public class VirgilCloudPureStorage implements PureStorage, PureModelSerializerDependent {

    // TODO: Map more service errors here

    /**
     * Returns PureModelSerializer
     *
     * @return PureModelSerializer
     */
    public PureModelSerializer getPureModelSerializer() {
        return pureModelSerializer;
    }

    @Override
    public void setPureModelSerializer(PureModelSerializer pureModelSerializer) {
        ValidateUtils.checkNull(pureModelSerializer, "pureModelSerializer");

        this.pureModelSerializer = pureModelSerializer;
    }

    private PureModelSerializer pureModelSerializer;
    private final HttpPureClient client;

    /**
     * Instantiates VirgilCloudPureStorage.
     *
     * @param client Pure http client
     */
    public VirgilCloudPureStorage(HttpPureClient client) {
        ValidateUtils.checkNull(client, "client");

        this.client = client;
    }

    @Override
    public void insertUser(UserRecord userRecord) throws PureStorageException {
        ValidateUtils.checkNull(userRecord, "userRecord");

        sendUser(userRecord, true);
    }

    @Override
    public void updateUser(UserRecord userRecord) throws PureStorageException {
        ValidateUtils.checkNull(userRecord, "userRecord");

        sendUser(userRecord, false);
    }

    @Override
    public void updateUsers(Iterable<UserRecord> userRecords, int previousPheVersion) throws PureStorageException {
        throw new UnsupportedOperationException(
                "This method always throws UnsupportedOperationException, as in case of using "
                        + "Virgil Cloud storage, rotation happens on the Virgil side."
        );
    }

    @Override
    public UserRecord selectUser(String userId) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");

        PurekitProtosV3Storage.UserRecord protobufRecord;

        try {
            protobufRecord = client.getUser(userId);
        } catch (ProtocolException e) {
            if (e.getErrorCode() == ServiceErrorCode.USER_NOT_FOUND.getCode()) {
                throw new PureStorageGenericException(
                        PureStorageGenericException.ErrorStatus.USER_NOT_FOUND
                );
            }

            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }

        UserRecord userRecord = pureModelSerializer.parseUserRecord(protobufRecord);

        if (!userRecord.getUserId().equals(userId)) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
        }

        return userRecord;
    }

    @Override
    public Iterable<UserRecord> selectUsers(Set<String> userIds) throws PureStorageException {
        ValidateUtils.checkNull(userIds, "userIds");

        if (userIds.isEmpty()) {
            return Collections.emptyList();
        }

        HashSet<String> idsSet = new HashSet<>(userIds);

        PurekitProtosV3Storage.UserRecords protoRecords;

        try {
            protoRecords = client.getUsers(userIds);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }

        if (protoRecords.getUserRecordsCount() != userIds.size()) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.DUPLICATE_USER_ID);
        }

        ArrayList<UserRecord> userRecords = new ArrayList<>(protoRecords.getUserRecordsCount());

        for (PurekitProtosV3Storage.UserRecord protobufRecord : protoRecords.getUserRecordsList()) {
            UserRecord userRecord = pureModelSerializer.parseUserRecord(protobufRecord);

            if (!idsSet.contains(userRecord.getUserId())) {
                throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
            }

            idsSet.remove(userRecord.getUserId());

            userRecords.add(userRecord);
        }

        return userRecords;
    }

    @Override
    public Iterable<UserRecord> selectUsers(int recordVersion) throws PureStorageException {
        throw new UnsupportedOperationException(
            "This method always throws UnsupportedOperationException, as in case of using "
                + "Virgil Cloud storage, rotation happens on the Virgil side."
        );
    }

    @Override
    public void deleteUser(String userId, boolean cascade) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");

        try {
            client.deleteUser(userId, cascade);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public CellKey selectCellKey(String userId, String dataId) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        PurekitProtosV3Storage.CellKey protobufRecord;
        try {
            protobufRecord = client.getCellKey(userId, dataId);
        } catch (ProtocolException e) {
            if (e.getErrorCode() == ServiceErrorCode.CELL_KEY_NOT_FOUND.getCode()) {
                throw new PureStorageCellKeyNotFoundException();
            }

            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }

        CellKey cellKey = pureModelSerializer.parseCellKey(protobufRecord);

        if (!userId.equals(cellKey.getUserId()) || !dataId.equals(cellKey.getDataId())) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.CELL_KEY_ID_MISMATCH);
        }

        return cellKey;
    }

    @Override
    public void insertCellKey(CellKey cellKey) throws PureStorageException {
        ValidateUtils.checkNull(cellKey, "cellKey");

        insertKey(cellKey, true);
    }

    @Override
    public void updateCellKey(CellKey cellKey) throws PureStorageException {
        ValidateUtils.checkNull(cellKey, "cellKey");

        insertKey(cellKey, false);
    }

    @Override
    public void deleteCellKey(String userId, String dataId) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");

        try {
            client.deleteCellKey(userId, dataId);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public void insertRole(Role role) throws PureStorageException {
        ValidateUtils.checkNull(role, "role");

        PurekitProtosV3Storage.Role protobufRecord = pureModelSerializer.serializeRole(role);

        try {
            client.insertRole(protobufRecord);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public Iterable<Role> selectRoles(Set<String> roleNames) throws PureStorageException {
        ValidateUtils.checkNull(roleNames, "roleNames");

        if (roleNames.isEmpty()) {
            return Collections.emptyList();
        }

        HashSet<String> namesSet = new HashSet<>(roleNames);

        PurekitProtosV3Storage.Roles protoRecords = null;
        try {
            protoRecords = client.getRoles(roleNames);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }

        if (protoRecords.getRolesCount() != roleNames.size()) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.DUPLICATE_ROLE_NAME);
        }

        ArrayList<Role> roles = new ArrayList<>(protoRecords.getRolesCount());

        for (PurekitProtosV3Storage.Role protobufRecord : protoRecords.getRolesList()) {
            Role role = pureModelSerializer.parseRole(protobufRecord);

            if (!namesSet.contains(role.getRoleName())) {
                throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.ROLE_NAME_MISMATCH);
            }

            namesSet.remove(role.getRoleName());

            roles.add(role);
        }

        return roles;
    }

    @Override
    public void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) throws PureStorageException {
        ValidateUtils.checkNull(roleAssignments, "roleAssignments");

        if (roleAssignments.isEmpty()) {
            return;
        }

        PurekitProtosV3Storage.RoleAssignments.Builder protobufBuilder = PurekitProtosV3Storage.RoleAssignments.newBuilder();

        for (RoleAssignment roleAssignment: roleAssignments) {
            protobufBuilder.addRoleAssignments(pureModelSerializer.serializeRoleAssignment(roleAssignment));
        }

        PurekitProtosV3Storage.RoleAssignments protobufRecord = protobufBuilder.build();

        try {
            client.insertRoleAssignments(protobufRecord);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");

        PurekitProtosV3Client.GetRoleAssignments request = PurekitProtosV3Client.GetRoleAssignments.newBuilder()
                .setUserId(userId)
                .build();

        PurekitProtosV3Storage.RoleAssignments protoRecords = null;
        try {
            protoRecords = client.getRoleAssignments(request);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }

        ArrayList<RoleAssignment> roleAssignments = new ArrayList<>(protoRecords.getRoleAssignmentsCount());

        for (PurekitProtosV3Storage.RoleAssignment protobufRecord : protoRecords.getRoleAssignmentsList()) {
            RoleAssignment roleAssignment = pureModelSerializer.parseRoleAssignment(protobufRecord);

            if (!roleAssignment.getUserId().equals(userId)) {
                throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
            }

            roleAssignments.add(roleAssignment);
        }

        return roleAssignments;
    }

    @Override
    public RoleAssignment selectRoleAssignment(String roleName, String userId) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(roleName, "roleName");
        ValidateUtils.checkNullOrEmpty(userId, "userId");

        PurekitProtosV3Client.GetRoleAssignment request = PurekitProtosV3Client.GetRoleAssignment.newBuilder()
                .setUserId(userId)
                .setRoleName(roleName)
                .build();

        PurekitProtosV3Storage.RoleAssignment protobufRecord;
        try {
            protobufRecord = client.getRoleAssignment(request);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }

        return pureModelSerializer.parseRoleAssignment(protobufRecord);
    }

    @Override
    public void deleteRoleAssignments(String roleName, Set<String> userIds) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(roleName, "roleName");
        ValidateUtils.checkNull(userIds, "userIds");

        if (userIds.isEmpty()) {
            return;
        }

        PurekitProtosV3Client.DeleteRoleAssignments request = PurekitProtosV3Client.DeleteRoleAssignments
                .newBuilder()
                .addAllUserIds(userIds)
                .setRoleName(roleName)
                .build();

        try {
            client.deleteRoleAssignments(request);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public void insertGrantKey(GrantKey grantKey) throws PureStorageException {
        ValidateUtils.checkNull(grantKey, "grantKey");

        PurekitProtosV3Storage.GrantKey protobufRecord = pureModelSerializer.serializeGrantKey(grantKey);

        try {
            client.insertGrantKey(protobufRecord);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public GrantKey selectGrantKey(String userId, byte[] keyId) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(keyId, "keyId");

        PurekitProtosV3Client.GrantKeyDescriptor request = PurekitProtosV3Client.GrantKeyDescriptor.newBuilder()
                .setUserId(userId)
                .setKeyId(ByteString.copyFrom(keyId))
                .build();

        PurekitProtosV3Storage.GrantKey protobufRecord;
        try {
            protobufRecord = client.getGrantKey(request);
        } catch (ProtocolException e) {
            if (e.getErrorCode() == ServiceErrorCode.GRANT_KEY_NOT_FOUND.getCode()) {
                throw new PureStorageGenericException(
                        PureStorageGenericException.ErrorStatus.GRANT_KEY_NOT_FOUND
                );
            }

            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }

        GrantKey grantKey = pureModelSerializer.parseGrantKey(protobufRecord);

        if (!grantKey.getUserId().equals(userId)) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
        }
        if (!Arrays.equals(grantKey.getKeyId(), keyId)) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.KEY_ID_MISMATCH);
        }

        return grantKey;
    }

    @Override
    public Iterable<GrantKey> selectGrantKeys(int recordVersion) throws PureStorageException {
        throw new UnsupportedOperationException(
                "This method always throws UnsupportedOperationException, as in case of using "
                        + "Virgil Cloud storage, rotation happens on the Virgil side."
        );
    }

    @Override
    public void updateGrantKeys(Iterable<GrantKey> grantKeys) throws PureStorageException {
        throw new UnsupportedOperationException(
                "This method always throws UnsupportedOperationException, as in case of using "
                        + "Virgil Cloud storage, rotation happens on the Virgil side."
        );
    }

    @Override
    public void deleteGrantKey(String userId, byte[] keyId) throws PureStorageException {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(keyId, "keyId");

        PurekitProtosV3Client.GrantKeyDescriptor request = PurekitProtosV3Client.GrantKeyDescriptor.newBuilder()
                .setUserId(userId)
                .setKeyId(ByteString.copyFrom(keyId))
                .build();

        try {
            client.deleteGrantKey(request);
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    private void sendUser(UserRecord userRecord, boolean isInsert) throws PureStorageException {

        PurekitProtosV3Storage.UserRecord protobufRecord = pureModelSerializer.serializeUserRecord(userRecord);

        try {
            if (isInsert) {
                client.insertUser(protobufRecord);
            } else {
                client.updateUser(userRecord.getUserId(), protobufRecord);
            }
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    private void insertKey(CellKey cellKey, boolean isInsert) throws PureStorageException {

        PurekitProtosV3Storage.CellKey protobufRecord = pureModelSerializer.serializeCellKey(cellKey);

        try {
            if (isInsert) {
                try {
                    client.insertCellKey(protobufRecord);
                } catch (ProtocolException e) {
                    if (e.getErrorCode() == ServiceErrorCode.CELL_KEY_ALREADY_EXISTS.getCode()) {

                        throw new PureStorageCellKeyAlreadyExistsException();
                    }

                    throw e;
                }
            } else {
                client.updateCellKey(cellKey.getUserId(), cellKey.getDataId(), protobufRecord);
            }
        } catch (ProtocolException e) {
            throw new VirgilCloudStorageException(e);
        } catch (ProtocolHttpException e) {
            throw new VirgilCloudStorageException(e);
        }
    }
}
