package com.virgilsecurity.purekit.pure.ramstorage;

import com.virgilsecurity.purekit.pure.PureStorage;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.*;
import sun.awt.image.ImageWatched;

import java.util.*;
import java.util.function.Predicate;

import static com.virgilsecurity.purekit.pure.exception.PureLogicException.ErrorStatus.GRANT_KEY_NOT_FOUND_IN_STORAGE;

public class RamPureStorage implements PureStorage {
    private HashMap<String, UserRecord> users;
    private HashMap<String, HashMap<String, CellKey>> keys;
    private HashMap<String, Role> roles;
    private HashMap<String, HashMap<String, RoleAssignment>> roleAssignments;
    private HashMap<String, HashMap<String, GrantKey>> grantKeys;

    public static int GRANT_KEYS_CLEAN_INTERVAL = 5000;

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

            for (Map.Entry<String, HashMap<String, GrantKey>> userGrantKeys: storage.grantKeys.entrySet()) {
                // TODO: Test
                userGrantKeys.getValue().entrySet().removeIf(entry -> entry.getValue().getExpirationDate().before(currentDate));
            }
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
    public UserRecord selectUser(String userId) throws PureException {
        UserRecord userRecord = this.users.get(userId);

        if (userRecord == null) {
            throw new PureLogicException(PureLogicException.ErrorStatus.USER_NOT_FOUND_IN_STORAGE);
        }

        return userRecord;
    }

    @Override
    public Collection<UserRecord> selectUsers(Set<String> userIds) {
        ArrayList<UserRecord> userRecords = new ArrayList<>(userIds.size());

        for (String userId: userIds) {
            UserRecord userRecord = this.users.get(userId);

            if (userRecord == null) {
                throw new NullPointerException();
            }

            userRecords.add(userRecord);
        }

        return userRecords;
    }

    public static Predicate<UserRecord> isNotVersion(Integer version) {
        return p -> p.getRecordVersion() != version;
    }

    @Override
    public Collection<UserRecord> selectUsers(int pheRecordVersion) {
        ArrayList<UserRecord> records = new ArrayList<>(this.users.values());
        records.removeIf(isNotVersion(pheRecordVersion));

        int limit = 10;

        return records.subList(0, Math.min(limit, records.size()));
    }

    @Override
    public void deleteUser(String userId, boolean cascade) {
        if (this.users.remove(userId) == null) {
            throw new NullPointerException();
        }

        if (cascade) {
            this.keys.remove(userId);
        }
    }

    @Override
    public CellKey selectCellKey(String userId, String dataId) {
        HashMap<String, CellKey> map = this.keys.get(userId);

        if (map == null) {
            return null;
        }

        return map.get(dataId);
    }

    @Override
    public void insertCellKey(CellKey cellKey) throws PureException {
        HashMap<String, CellKey> map = this.keys.getOrDefault(cellKey.getUserId(), new HashMap<>());

        if (map.putIfAbsent(cellKey.getDataId(), cellKey) != null) {
            throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
        }

        this.keys.put(cellKey.getUserId(), map);
    }

    @Override
    public void updateCellKey(CellKey cellKey) throws PureException {
        HashMap<String, CellKey> map = this.keys.get(cellKey.getUserId());

        if (!map.containsKey(cellKey.getDataId())) {
            throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
        }

        map.put(cellKey.getDataId(), cellKey);
    }

    @Override
    public void deleteCellKey(String userId, String dataId) {
        HashMap<String, CellKey> keys = this.keys.get(userId);

        if (keys == null) {
            throw new NullPointerException();
        }

        if (keys.remove(dataId) == null) {
            throw new NullPointerException();
        }
    }

    @Override
    public void insertRole(Role role) throws Exception {
        this.roles.put(role.getRoleName(), role);
    }

    @Override
    public Iterable<Role> selectRoles(Set<String> roleNames) throws Exception {

        ArrayList<Role> roles = new ArrayList<>(roleNames.size());

        for (String roleName: roleNames) {
            Role role = this.roles.get(roleName);

            if (role == null) {
                throw new NullPointerException();
            }

            roles.add(role);
        }

        return roles;
    }

    @Override
    public void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) throws Exception {

        for (RoleAssignment roleAssignment: roleAssignments) {
            HashMap<String, RoleAssignment> map = this.roleAssignments.getOrDefault(roleAssignment.getRoleName(), new HashMap<>());

            map.put(roleAssignment.getUserId(), roleAssignment);

            this.roleAssignments.put(roleAssignment.getRoleName(), map);
        }
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) throws Exception {
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
    public RoleAssignment selectRoleAssignment(String roleName, String userId) throws Exception {

        return this.roleAssignments.get(roleName).get(userId);
    }

    @Override
    public void deleteRoleAssignments(String roleName, Set<String> userIds) throws Exception {

        HashMap<String, RoleAssignment> map = this.roleAssignments.getOrDefault(roleName, new HashMap<>());

        for (String userId: userIds) {
            map.remove(userId);
        }

        this.roleAssignments.put(roleName, map);
    }

    @Override
    public void insertGrantKey(GrantKey grantKey) throws Exception {
        HashMap<String, GrantKey> keys = this.grantKeys.getOrDefault(grantKey.getUserId(), new HashMap<>());

        keys.put(Base64.getEncoder().encodeToString(grantKey.getKeyId()), grantKey);

        this.grantKeys.put(grantKey.getUserId(), keys);
    }

    @Override
    public GrantKey selectGrantKey(String userId, byte[] keyId) throws Exception {
        HashMap<String, GrantKey> keys = this.grantKeys.get(userId);

        GrantKey key = keys.get(Base64.getEncoder().encodeToString(keyId));

        if (key == null || key.getExpirationDate().before(new Date())) {
            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_KEY_NOT_FOUND_IN_STORAGE);
        }

        return key;
    }

    @Override
    public void deleteGrantKey(String userId, byte[] keyId) throws Exception {
        HashMap<String, GrantKey> keys = this.grantKeys.get(userId);

        keys.remove(Base64.getEncoder().encodeToString(keyId));

        grantKeys.put(userId, keys);
    }
}
