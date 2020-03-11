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

package com.virgilsecurity.purekit.storage.ram;

import com.virgilsecurity.purekit.model.CellKey;
import com.virgilsecurity.purekit.model.GrantKey;
import com.virgilsecurity.purekit.model.Role;
import com.virgilsecurity.purekit.model.RoleAssignment;
import com.virgilsecurity.purekit.model.UserRecord;
import com.virgilsecurity.purekit.storage.PureStorage;
import com.virgilsecurity.purekit.storage.exception.PureStorageCellKeyAlreadyExistsException;
import com.virgilsecurity.purekit.storage.exception.PureStorageCellKeyNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageException;
import com.virgilsecurity.purekit.storage.exception.PureStorageGrantKeyNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageRoleAssignmentNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageRoleNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageUserNotFoundException;
import com.virgilsecurity.purekit.storage.mariadb.MariaDbPureStorage;
import com.virgilsecurity.purekit.storage.virgil.VirgilCloudPureStorage;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Predicate;

/**
 * PureStorage implementation that stores data in RAM.
 * <blockquote>Use this implementation only to try out Pure.</blockquote>
 * For any real-world usage please see {@link VirgilCloudPureStorage}, {@link MariaDbPureStorage}
 * or implement {@link PureStorage} yourself.
 */
public class RamPureStorage implements PureStorage {
    private HashMap<String, UserRecord> users;
    private HashMap<String, HashMap<String, CellKey>> keys;
    private HashMap<String, Role> roles;
    private HashMap<String, HashMap<String, RoleAssignment>> roleAssignments;
    private HashMap<String, GrantKey> grantKeys;

    public static int GRANT_KEYS_CLEAN_INTERVAL = 20000;

    /**
     * Constructor
     */
    public RamPureStorage() {
        this.users = new HashMap<>();
        this.keys = new HashMap<>();
        this.roles = new HashMap<>();
        this.roleAssignments = new HashMap<>();
        this.grantKeys = new HashMap<>();
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new CleanGrantKeys(this), 0, GRANT_KEYS_CLEAN_INTERVAL);
    }

    static class CleanGrantKeys extends TimerTask {

        private final RamPureStorage storage;

        public CleanGrantKeys(RamPureStorage storage) {
            this.storage = storage;
        }

        @Override
        public void run() {
            Date currentDate = new Date();

            storage.grantKeys.entrySet().removeIf(entry -> entry.getValue().getExpirationDate().before(currentDate));
        }
    }

    @Override
    public void insertUser(UserRecord userRecord) {
        this.users.put(userRecord.getUserId(), userRecord);
    }

    @Override
    public void updateUser(UserRecord userRecord) {
        this.users.put(userRecord.getUserId(), userRecord);
    }

    @Override
    public void updateUsers(Iterable<UserRecord> userRecords, int previousPheVersion) {
        for (UserRecord userRecord: userRecords) {
            updateUser(userRecord);
        }
    }

    @Override
    public UserRecord selectUser(String userId) throws PureStorageException {
        UserRecord userRecord = this.users.get(userId);

        if (userRecord == null) {
            throw new PureStorageUserNotFoundException(userId);
        }

        return userRecord;
    }

    @Override
    public Collection<UserRecord> selectUsers(Set<String> userIds) throws PureStorageException {
        ArrayList<UserRecord> userRecords = new ArrayList<>(userIds.size());

        for (String userId: userIds) {
            UserRecord userRecord = this.users.get(userId);

            if (userRecord == null) {
                throw new PureStorageUserNotFoundException(userId);
            }

            userRecords.add(userRecord);
        }

        return userRecords;
    }

    public static Predicate<UserRecord> isNotVersion(Integer version) {
        return p -> p.getRecordVersion() != version;
    }

    @Override
    public Collection<UserRecord> selectUsers(int recordVersion) {
        ArrayList<UserRecord> records = new ArrayList<>(this.users.values());
        records.removeIf(isNotVersion(recordVersion));

        int limit = 10;

        return records.subList(0, Math.min(limit, records.size()));
    }

    @Override
    public void deleteUser(String userId, boolean cascade) throws PureStorageException {
        if (this.users.remove(userId) == null) {
            throw new PureStorageUserNotFoundException(userId);
        }

        if (cascade) {
            this.keys.remove(userId);
        }
    }

    @Override
    public CellKey selectCellKey(String userId, String dataId) throws PureStorageException {
        HashMap<String, CellKey> map = this.keys.get(userId);

        if (map == null) {
            throw new PureStorageCellKeyNotFoundException();
        }

        CellKey cellKey = map.get(dataId);

        if (cellKey == null) {
            throw new PureStorageCellKeyNotFoundException();
        }

        return cellKey;
    }

    @Override
    public void insertCellKey(CellKey cellKey) throws PureStorageException {
        HashMap<String, CellKey> map = this.keys.getOrDefault(cellKey.getUserId(), new HashMap<>());

        if (map.putIfAbsent(cellKey.getDataId(), cellKey) != null) {
            throw new PureStorageCellKeyAlreadyExistsException();
        }

        this.keys.put(cellKey.getUserId(), map);
    }

    @Override
    public void updateCellKey(CellKey cellKey) throws PureStorageException {
        HashMap<String, CellKey> map = this.keys.get(cellKey.getUserId());

        if (!map.containsKey(cellKey.getDataId())) {
            throw new PureStorageCellKeyNotFoundException();
        }

        map.put(cellKey.getDataId(), cellKey);
    }

    @Override
    public void deleteCellKey(String userId, String dataId) throws PureStorageException {
        HashMap<String, CellKey> keys = this.keys.get(userId);

        if (keys == null) {
            throw new PureStorageCellKeyNotFoundException();
        }

        if (keys.remove(dataId) == null) {
            throw new PureStorageCellKeyNotFoundException();
        }
    }

    @Override
    public void insertRole(Role role) {
        this.roles.put(role.getRoleName(), role);
    }

    @Override
    public Set<Role> selectRoles(Set<String> roleNames) throws PureStorageException {

        Set<Role> roles = new HashSet<>(roleNames.size());

        for (String roleName: roleNames) {
            Role role = this.roles.get(roleName);

            if (role == null) {
                throw new PureStorageRoleNotFoundException(roleName);
            }

            roles.add(role);
        }

        return roles;
    }

    @Override
    public void deleteRole(String roleName) throws PureStorageException {
        this.roles.remove(roleName);
        this.roleAssignments.remove(roleName);
    }

    @Override
    public void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) {

        for (RoleAssignment roleAssignment: roleAssignments) {
            HashMap<String, RoleAssignment> map = this.roleAssignments.getOrDefault(roleAssignment.getRoleName(), new HashMap<>());

            map.put(roleAssignment.getUserId(), roleAssignment);

            this.roleAssignments.put(roleAssignment.getRoleName(), map);
        }
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) {
        Set<String> roleNames = this.roleAssignments.keySet();
        ArrayList<RoleAssignment> assignments = new ArrayList<>();

        for (String roleName: roleNames) {
            HashMap<String, RoleAssignment> roleAssignments = this.roleAssignments.get(roleName);
            RoleAssignment assignment = roleAssignments.get(userId);

            if (assignment != null) {
                assignments.add(assignment);
            }
        }

        return assignments;
    }

    @Override
    public RoleAssignment selectRoleAssignment(String roleName, String userId) throws PureStorageException {

        HashMap<String, RoleAssignment> assignments = this.roleAssignments.get(roleName);

        if (assignments == null) {
            throw new PureStorageRoleAssignmentNotFoundException(userId, roleName);
        }

        RoleAssignment roleAssignment = assignments.get(userId);

        if (roleAssignment == null) {
            throw new PureStorageRoleAssignmentNotFoundException(userId, roleName);
        }

        return roleAssignment;
    }

    @Override
    public void deleteRoleAssignments(String roleName, Set<String> userIds) {

        HashMap<String, RoleAssignment> map = this.roleAssignments.getOrDefault(roleName, new HashMap<>());

        for (String userId: userIds) {
            map.remove(userId);
        }

        this.roleAssignments.put(roleName, map);
    }

    @Override
    public void insertGrantKey(GrantKey grantKey) {
        this.grantKeys.put(Base64.getEncoder().encodeToString(grantKey.getKeyId()), grantKey);
    }

    @Override
    public GrantKey selectGrantKey(String userId, byte[] keyId) throws PureStorageException {
        GrantKey key = grantKeys.get(Base64.getEncoder().encodeToString(keyId));

        if (key == null) {
            throw new PureStorageGrantKeyNotFoundException(userId, keyId);
        }

        assert userId.equals(key.getUserId());

        return key;
    }

    public static Predicate<GrantKey> isNotGrantVersion(Integer version) {
        return p -> p.getRecordVersion() != version;
    }

    @Override
    public Iterable<GrantKey> selectGrantKeys(int recordVersion) throws PureStorageException {
        ArrayList<GrantKey> records = new ArrayList<>(this.grantKeys.values());
        records.removeIf(isNotGrantVersion(recordVersion));

        int limit = 10;

        return records.subList(0, Math.min(limit, records.size()));
    }

    @Override
    public void updateGrantKeys(Iterable<GrantKey> grantKeys) throws PureStorageException {
        for (GrantKey grantKey: grantKeys) {
            this.grantKeys.put(Base64.getEncoder().encodeToString(grantKey.getKeyId()), grantKey);
        }
    }

    @Override
    public void deleteGrantKey(String userId, byte[] keyId) {
        grantKeys.remove(Base64.getEncoder().encodeToString(keyId));
    }
}
