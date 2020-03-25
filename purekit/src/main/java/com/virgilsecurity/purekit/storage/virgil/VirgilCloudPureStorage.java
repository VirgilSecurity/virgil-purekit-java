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

package com.virgilsecurity.purekit.storage.virgil;

import com.google.protobuf.ByteString;
import com.virgilsecurity.purekit.client.HttpClientException;
import com.virgilsecurity.purekit.client.HttpClientServiceException;
import com.virgilsecurity.purekit.client.HttpPureClient;
import com.virgilsecurity.purekit.client.ServiceErrorCode;
import com.virgilsecurity.purekit.model.CellKey;
import com.virgilsecurity.purekit.model.GrantKey;
import com.virgilsecurity.purekit.model.Role;
import com.virgilsecurity.purekit.model.RoleAssignment;
import com.virgilsecurity.purekit.model.UserRecord;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Client;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.storage.PureModelSerializer;
import com.virgilsecurity.purekit.storage.PureModelSerializerDependent;
import com.virgilsecurity.purekit.storage.PureStorage;
import com.virgilsecurity.purekit.storage.exception.PureStorageCellKeyAlreadyExistsException;
import com.virgilsecurity.purekit.storage.exception.PureStorageCellKeyNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageException;
import com.virgilsecurity.purekit.storage.exception.PureStorageGenericException;
import com.virgilsecurity.purekit.storage.exception.PureStorageGrantKeyNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageRoleAssignmentNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageRoleNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageUserNotFoundException;
import com.virgilsecurity.purekit.utils.ValidationUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * PureStorage on Virgil cloud side
 */
public class VirgilCloudPureStorage implements PureStorage, PureModelSerializerDependent {
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
        ValidationUtils.checkNull(pureModelSerializer, "pureModelSerializer");

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
        ValidationUtils.checkNull(client, "client");

        this.client = client;
    }

    @Override
    public void insertUser(UserRecord userRecord) throws PureStorageException {
        ValidationUtils.checkNull(userRecord, "userRecord");

        sendUser(userRecord, true);
    }

    @Override
    public void updateUser(UserRecord userRecord) throws PureStorageException {
        ValidationUtils.checkNull(userRecord, "userRecord");

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
        ValidationUtils.checkNullOrEmpty(userId, "userId");

        PurekitProtosV3Storage.UserRecord protobufRecord;

        PurekitProtosV3Client.GetUserRequest request = PurekitProtosV3Client.GetUserRequest.newBuilder()
                .setUserId(userId)
                .build();

        try {
            protobufRecord = client.getUser(request);
        } catch (HttpClientServiceException e) {
            if (e.getErrorCode() == ServiceErrorCode.USER_NOT_FOUND.getCode()) {
                throw new PureStorageUserNotFoundException(userId);
            }

            throw new VirgilCloudStorageException(e);
        } catch (HttpClientException e) {
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
        ValidationUtils.checkNull(userIds, "userIds");

        if (userIds.isEmpty()) {
            return Collections.emptyList();
        }

        PurekitProtosV3Client.GetUsersRequest request = PurekitProtosV3Client.GetUsersRequest.newBuilder()
                .addAllUserIds(userIds)
                .build();

        HashSet<String> idsSet = new HashSet<>(userIds);

        PurekitProtosV3Storage.UserRecords protoRecords;

        try {
            protoRecords = client.getUsers(request);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }

        if (protoRecords.getUserRecordsCount() != userIds.size()) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_COUNT_MISMATCH);
        }

        ArrayList<UserRecord> userRecords = new ArrayList<>(protoRecords.getUserRecordsCount());

        for (PurekitProtosV3Storage.UserRecord protobufRecord : protoRecords.getUserRecordsList()) {
            UserRecord userRecord = pureModelSerializer.parseUserRecord(protobufRecord);

            if (!idsSet.remove(userRecord.getUserId())) {
                throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
            }

            userRecords.add(userRecord);
        }

        if (!idsSet.isEmpty()) {
            throw new PureStorageUserNotFoundException(idsSet);
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
        ValidationUtils.checkNullOrEmpty(userId, "userId");

        PurekitProtosV3Client.DeleteUserRequest request = PurekitProtosV3Client.DeleteUserRequest.newBuilder()
                .setUserId(userId)
                .build();

        try {
            client.deleteUser(request, cascade);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public CellKey selectCellKey(String userId, String dataId) throws PureStorageException {
        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(dataId, "dataId");

        PurekitProtosV3Client.GetCellKeyRequest request = PurekitProtosV3Client.GetCellKeyRequest.newBuilder()
                .setUserId(userId)
                .setDataId(dataId)
                .build();

        PurekitProtosV3Storage.CellKey protobufRecord;
        try {
            protobufRecord = client.getCellKey(request);
        } catch (HttpClientServiceException e) {
            if (e.getErrorCode() == ServiceErrorCode.CELL_KEY_NOT_FOUND.getCode()) {
                throw new PureStorageCellKeyNotFoundException();
            }

            throw new VirgilCloudStorageException(e);
        } catch (HttpClientException e) {
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
        ValidationUtils.checkNull(cellKey, "cellKey");

        insertKey(cellKey, true);
    }

    @Override
    public void updateCellKey(CellKey cellKey) throws PureStorageException {
        ValidationUtils.checkNull(cellKey, "cellKey");

        insertKey(cellKey, false);
    }

    @Override
    public void deleteCellKey(String userId, String dataId) throws PureStorageException {
        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(dataId, "dataId");

        PurekitProtosV3Client.DeleteCellKeyRequest request = PurekitProtosV3Client.DeleteCellKeyRequest.newBuilder()
                .setUserId(userId)
                .setDataId(dataId)
                .build();

        try {
            client.deleteCellKey(request);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public void insertRole(Role role) throws PureStorageException {
        ValidationUtils.checkNull(role, "role");

        PurekitProtosV3Storage.Role protobufRecord = pureModelSerializer.serializeRole(role);

        try {
            client.insertRole(protobufRecord);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public Set<Role> selectRoles(Set<String> roleNames) throws PureStorageException {
        ValidationUtils.checkNull(roleNames, "roleNames");

        if (roleNames.isEmpty()) {
            return Collections.emptySet();
        }

        PurekitProtosV3Client.GetRolesRequest getRolesRequest =
                PurekitProtosV3Client.GetRolesRequest.newBuilder().addAllRoleNames(roleNames).build();

        HashSet<String> namesSet = new HashSet<>(roleNames);

        PurekitProtosV3Storage.Roles protoRecords;
        try {
            protoRecords = client.getRoles(getRolesRequest);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }

        if (protoRecords.getRolesCount() != roleNames.size()) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.DUPLICATE_ROLE_NAME);
        }

        Set<Role> roles = new HashSet<>(protoRecords.getRolesCount());

        for (PurekitProtosV3Storage.Role protobufRecord : protoRecords.getRolesList()) {
            Role role = pureModelSerializer.parseRole(protobufRecord);

            if (!namesSet.remove(role.getRoleName())) {
                throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.ROLE_NAME_MISMATCH);
            }

            roles.add(role);
        }

        if (!namesSet.isEmpty()) {
            throw new PureStorageRoleNotFoundException(namesSet);
        }

        return roles;
    }

    @Override
    public void deleteRole(String roleName) throws PureStorageException {
        ValidationUtils.checkNullOrEmpty(roleName, "roleName");

        PurekitProtosV3Client.DeleteRoleRequest protobuf = PurekitProtosV3Client.DeleteRoleRequest.newBuilder()
                .setName(roleName)
                .build();

        try {
            client.deleteRole(protobuf);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) throws PureStorageException {
        ValidationUtils.checkNull(roleAssignments, "roleAssignments");

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
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) throws PureStorageException {
        ValidationUtils.checkNullOrEmpty(userId, "userId");

        PurekitProtosV3Client.GetRoleAssignmentsRequest request = PurekitProtosV3Client.GetRoleAssignmentsRequest.newBuilder()
                .setUserId(userId)
                .build();

        PurekitProtosV3Storage.RoleAssignments protoRecords = null;
        try {
            protoRecords = client.getRoleAssignments(request);
        } catch (HttpClientException e) {
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
        ValidationUtils.checkNullOrEmpty(roleName, "roleName");
        ValidationUtils.checkNullOrEmpty(userId, "userId");

        PurekitProtosV3Client.GetRoleAssignmentRequest request = PurekitProtosV3Client.GetRoleAssignmentRequest.newBuilder()
                .setUserId(userId)
                .setRoleName(roleName)
                .build();

        PurekitProtosV3Storage.RoleAssignment protobufRecord;
        try {
            protobufRecord = client.getRoleAssignment(request);
        } catch (HttpClientServiceException e) {
            if (e.getErrorCode() == ServiceErrorCode.ROLE_ASSIGNMENT_NOT_FOUND.getCode()) {
                throw new PureStorageRoleAssignmentNotFoundException(userId, roleName);
            }

            throw new VirgilCloudStorageException(e);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }

        RoleAssignment roleAssignment = pureModelSerializer.parseRoleAssignment(protobufRecord);

        if (!roleAssignment.getUserId().equals(userId)) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
        }

        if (!roleAssignment.getRoleName().equals(roleName)) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.ROLE_NAME_MISMATCH);
        }

        return roleAssignment;
    }

    @Override
    public void deleteRoleAssignments(String roleName, Set<String> userIds) throws PureStorageException {
        ValidationUtils.checkNullOrEmpty(roleName, "roleName");
        ValidationUtils.checkNull(userIds, "userIds");

        if (userIds.isEmpty()) {
            return;
        }

        PurekitProtosV3Client.DeleteRoleAssignmentsRequest request = PurekitProtosV3Client.DeleteRoleAssignmentsRequest
                .newBuilder()
                .addAllUserIds(userIds)
                .setRoleName(roleName)
                .build();

        try {
            client.deleteRoleAssignments(request);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public void insertGrantKey(GrantKey grantKey) throws PureStorageException {
        ValidationUtils.checkNull(grantKey, "grantKey");

        PurekitProtosV3Storage.GrantKey protobufRecord = pureModelSerializer.serializeGrantKey(grantKey);

        try {
            client.insertGrantKey(protobufRecord);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    @Override
    public GrantKey selectGrantKey(String userId, byte[] keyId) throws PureStorageException {
        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(keyId, "keyId");

        PurekitProtosV3Client.GetGrantKeyRequest request = PurekitProtosV3Client.GetGrantKeyRequest.newBuilder()
                .setUserId(userId)
                .setKeyId(ByteString.copyFrom(keyId))
                .build();

        PurekitProtosV3Storage.GrantKey protobufRecord;
        try {
            protobufRecord = client.getGrantKey(request);
        } catch (HttpClientServiceException e) {
            if (e.getErrorCode() == ServiceErrorCode.GRANT_KEY_NOT_FOUND.getCode()) {
                throw new PureStorageGrantKeyNotFoundException(userId, keyId);
            }

            throw new VirgilCloudStorageException(e);
        } catch (HttpClientException e) {
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
        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(keyId, "keyId");

        PurekitProtosV3Client.DeleteGrantKeyRequest request = PurekitProtosV3Client.DeleteGrantKeyRequest.newBuilder()
                .setUserId(userId)
                .setKeyId(ByteString.copyFrom(keyId))
                .build();

        try {
            client.deleteGrantKey(request);
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    private void sendUser(UserRecord userRecord, boolean isInsert) throws PureStorageException {

        PurekitProtosV3Storage.UserRecord protobufRecord = pureModelSerializer.serializeUserRecord(userRecord);

        try {
            if (isInsert) {
                client.insertUser(protobufRecord);
            } else {
                client.updateUser(protobufRecord);
            }
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }

    private void insertKey(CellKey cellKey, boolean isInsert) throws PureStorageException {

        PurekitProtosV3Storage.CellKey protobufRecord = pureModelSerializer.serializeCellKey(cellKey);

        try {
            if (isInsert) {
                try {
                    client.insertCellKey(protobufRecord);
                } catch (HttpClientServiceException e) {
                    if (e.getErrorCode() == ServiceErrorCode.CELL_KEY_ALREADY_EXISTS.getCode()) {

                        throw new PureStorageCellKeyAlreadyExistsException();
                    }

                    throw e;
                }
            } else {
                client.updateCellKey(protobufRecord);
            }
        } catch (HttpClientException e) {
            throw new VirgilCloudStorageException(e);
        }
    }
}
