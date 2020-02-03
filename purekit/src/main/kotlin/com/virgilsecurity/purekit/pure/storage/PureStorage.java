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

package com.virgilsecurity.purekit.pure.storage;

import java.util.Collection;
import java.util.Set;

import com.virgilsecurity.purekit.pure.model.*;

/**
 * Interface for Pure storage.
 */
public interface PureStorage {

    /**
     * Insert a new user into a storage.
     *
     * @param userRecord User record.
     * @throws PureStorageException PureStorageException
     */
    void insertUser(UserRecord userRecord) throws PureStorageException;

    /**
     * Updates a user in a storage.
     *
     * @param userRecord User record.
     * @throws PureStorageException PureStorageException
     */
    void updateUser(UserRecord userRecord) throws PureStorageException;

    /**
     * Updates users in a storage.
     *
     * @param userRecords User record.
     * @param previousRecordVersion previous record version
     * @throws PureStorageException PureStorageException
     */
    void updateUsers(Iterable<UserRecord> userRecords, int previousRecordVersion) throws PureStorageException;

    /**
     * Obtains a user record with the given userId from a storage.
     *
     * @param userId User Id.
     *
     * @return UserRecord.
     *
     * @throws PureStorageException PureStorageException
     */
    UserRecord selectUser(String userId) throws PureStorageException;

    /**
     * Obtains users records with given userIds from a storage.
     *
     * @param userIds User Ids.
     *
     * @return UserRecords.
     *
     * @throws PureStorageException PureStorageException
     */
    Iterable<UserRecord> selectUsers(Set<String> userIds) throws PureStorageException;

    /**
     * Obtains users records with given recordVersion from a storage.
     *
     * @param recordVersion record version.
     *
     * @return UserRecords.
     *
     * @throws PureStorageException PureStorageException
     */
    Iterable<UserRecord> selectUsers(int recordVersion) throws PureStorageException;

    /**
     * Deletes user with the given id.
     *
     * @param userId User Id.
     * @param cascade Deletes all user cell keys if true.
     *
     * @throws PureStorageException PureStorageException
     */
    void deleteUser(String userId, boolean cascade) throws PureStorageException;

    /**
     * Obtains a CellKey for the given userId and dataId from a storage.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @return CellKey.
     *
     * @throws PureStorageException PureStorageException
     */
    CellKey selectCellKey(String userId, String dataId) throws PureStorageException;

    /**
     * Insert a CellKey key into a storage.
     *
     * @implSpec this method MUST throw {@link PureStorageCellKeyNotFoundException} if key with given
     * userId and dataId already exists.
     *
     * @param cellKey Cell key record.
     *
     * @throws PureStorageException PureStorageException
     */
    void insertCellKey(CellKey cellKey) throws PureStorageException;

    /**
     * Updates a CellKey.
     *
     * @param cellKey Cell key record.
     *
     * @throws PureStorageException PureStorageException
     */
    void updateCellKey(CellKey cellKey) throws PureStorageException;

    /**
     * Deletes a CellKey with the given userId and dataId.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @throws PureStorageException PureStorageException
     */
    void deleteCellKey(String userId, String dataId) throws PureStorageException;

    /**
     * Insert a Role into a storage.
     *
     * @param role Role record.
     *
     * @throws PureStorageException PureStorageException
     */
    void insertRole(Role role) throws PureStorageException;

    /**
     * Obtains a Role for the given name from a storage.
     *
     * @param roleNames role name
     *
     * @return Role record
     *
     * @throws PureStorageException PureStorageException
     */
    Iterable<Role> selectRoles(Set<String> roleNames) throws PureStorageException;

    /**
     * Insert a Role assignment into a storage.
     *
     * @param roleAssignments RoleAssignment record
     *
     * @throws PureStorageException PureStorageException
     */
    void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) throws PureStorageException;

    /**
     * Obtains all role assignments for the given user from a storage.
     *
     * @param userId user id
     *
     * @return RoleAssignment record
     *
     * @throws PureStorageException PureStorageException
     */
    Iterable<RoleAssignment> selectRoleAssignments(String userId) throws PureStorageException;

    /**
     * Obtains role assignment for the given user and role name from a storage.
     *
     * @param roleName role name
     * @param userId user id
     *
     * @return RoleAssignment record
     *
     * @throws PureStorageException PureStorageException
     */
    RoleAssignment selectRoleAssignment(String roleName, String userId) throws PureStorageException;

    /**
     * Deletes role assignments for the given role and user ids from a storage.
     *
     * @param roleName role name
     * @param userIds user ids
     *
     * @throws PureStorageException PureStorageException
     */
    void deleteRoleAssignments(String roleName, Set<String> userIds) throws PureStorageException;

    /**
     * Inserts grant key into a storage.
     *
     * @param grantKey GrantKey record
     *
     * @throws PureStorageException PureStorageException
     */
    void insertGrantKey(GrantKey grantKey) throws PureStorageException;

    /**
     * Obtains GrantKey from a storage.
     *
     * @param userId user id
     * @param keyId key id
     *
     * @return GrantKey record
     *
     * @throws PureStorageException PureStorageException
     */
    GrantKey selectGrantKey(String userId, byte[] keyId) throws PureStorageException;

    /**
     * Deletes GrantKey from a storage.
     *
     * @param userId user id
     * @param keyId key id
     *
     * @throws PureStorageException PureStorageException
     */
    void deleteGrantKey(String userId, byte[] keyId) throws PureStorageException;
}
