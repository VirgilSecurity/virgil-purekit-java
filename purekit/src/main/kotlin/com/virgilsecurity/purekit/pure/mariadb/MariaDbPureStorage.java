package com.virgilsecurity.purekit.pure.mariadb;

import com.virgilsecurity.purekit.pure.PureStorage;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.CellKey;
import com.virgilsecurity.purekit.pure.model.Role;
import com.virgilsecurity.purekit.pure.model.RoleAssignment;
import com.virgilsecurity.purekit.pure.model.UserRecord;

import org.mariadb.jdbc.*;

import javax.xml.transform.Result;
import java.sql.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

public class MariaDbPureStorage implements PureStorage {
    private String url;

    public MariaDbPureStorage(String url) {
        this.url = url;
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(url);
    }

    @Override
    public void insertUser(UserRecord userRecord) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_users (" +
                    "user_id," +
                    "phe_record," +
                    "phe_record_version," +
                    "upk," +
                    "encrypted_usk," +
                    "encrypted_usk_bkp," +
                    "encrypted_pwd_hash) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?);")) {

                stmt.setString(1, userRecord.getUserId());
                stmt.setBytes(2, userRecord.getPheRecord());
                stmt.setInt(3, userRecord.getPheRecordVersion());
                stmt.setBytes(4, userRecord.getUpk());
                stmt.setBytes(5, userRecord.getEncryptedUsk());
                stmt.setBytes(6, userRecord.getEncryptedUskBackup());
                stmt.setBytes(7, userRecord.getEncryptedPwdHash());

                stmt.executeUpdate();
            }
        }
    }

    @Override
    public void updateUser(UserRecord userRecord) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("UPDATE virgil_users " +
                    "SET phe_record=?," +
                    "phe_record_version=?," +
                    "encrypted_usk=?," +
                    "encrypted_pwd_hash=? " +
                    "WHERE user_id=?;")) {

                stmt.setBytes(1, userRecord.getPheRecord());
                stmt.setInt(2, userRecord.getPheRecordVersion());
                stmt.setBytes(3, userRecord.getEncryptedUsk());
                stmt.setBytes(4, userRecord.getEncryptedPwdHash());
                stmt.setString(5, userRecord.getUserId());

                stmt.executeUpdate();
            }
        }
    }

    private static UserRecord parseUserRecord(String userId, ResultSet rs) throws SQLException {
        int i = 0;
        if (userId == null) {
            userId = rs.getString(1);
            i = 1;
        }

        return new UserRecord(userId,
                rs.getBytes(i + 1), rs.getInt(i + 2), rs.getBytes(i + 3),
                rs.getBytes(i + 4), rs.getBytes(i + 5), rs.getBytes(i + 6));
    }

    @Override
    public UserRecord selectUser(String userId) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT phe_record, phe_record_version, upk, encrypted_usk, encrypted_usk_bkp, encrypted_pwd_hash " +
                    "FROM virgil_users " +
                    "WHERE user_id=?;")) {

                stmt.setString(1, userId);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return parseUserRecord(userId, rs);
                    }
                    else {
                        throw new PureLogicException(PureLogicException.ErrorStatus.USER_NOT_FOUND_IN_STORAGE);
                    }
                }
            }
        }
    }

    @Override
    public Iterable<UserRecord> selectUsers(Set<String> userIds) throws Exception {
        if (userIds.isEmpty()) {
            return new ArrayList<>();
        }

        try (Connection conn = getConnection()) {
            StringBuilder sbSql = new StringBuilder( 512 );
            sbSql.append("SELECT user_id, phe_record, phe_record_version, upk, encrypted_usk, encrypted_usk_bkp, encrypted_pwd_hash " +
                    "FROM virgil_users " +
                    "WHERE user_id in (" );

            for (int i = 0; i < userIds.size(); i++) {
                if (i > 0) sbSql.append(",");
                sbSql.append("?");
            }
            sbSql.append(");");

            try (PreparedStatement stmt = conn.prepareStatement(sbSql.toString())) {
                int i = 1;
                for (String userId: userIds) {
                    stmt.setString(i++, userId);
                }

                try (ResultSet rs = stmt.executeQuery()) {
                    ArrayList<UserRecord> userRecords = new ArrayList<>();
                    while (rs.next()) {
                        userRecords.add(parseUserRecord(null, rs));
                    }

                    return userRecords;
                }
            }
        }
    }

    @Override
    public Iterable<UserRecord> selectUsers(int pheRecordVersion) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT user_id, phe_record, phe_record_version, upk, encrypted_usk, encrypted_usk_bkp, encrypted_pwd_hash " +
                    "FROM virgil_users " +
                    "WHERE phe_record_version=? " +
                    "LIMIT 1000;")) {

                stmt.setInt(1, pheRecordVersion);

                try (ResultSet rs = stmt.executeQuery()) {
                    ArrayList<UserRecord> userRecords = new ArrayList<>();
                    while (rs.next()) {
                        userRecords.add(parseUserRecord(null, rs));
                    }

                    return userRecords;
                }
            }
        }
    }

    @Override
    public void deleteUser(String userId, boolean cascade) throws Exception {
        if (!cascade) {
            // FIXME
            throw new NullPointerException();
        }

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM virgil_users WHERE user_id = ?;")) {
                stmt.setString(1, userId);

                stmt.executeUpdate();
            }
        }
    }

    @Override
    public CellKey selectKey(String userId, String dataId) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT cpk, encrypted_csk_cms, encrypted_csk_body " +
                    "FROM virgil_keys " +
                    "WHERE user_id=? AND data_id=?;")) {

                stmt.setString(1, userId);
                stmt.setString(2, dataId);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return new CellKey(rs.getBytes(1), rs.getBytes(2), rs.getBytes(3));
                    }
                    else {
                        return null;
                    }
                }
            }
        }
    }

    @Override
    public void insertKey(String userId, String dataId, CellKey cellKey) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_keys (" +
                    "user_id," +
                    "data_id," +
                    "cpk," +
                    "encrypted_csk_cms," +
                    "encrypted_csk_body) " +
                    "VALUES (?, ?, ?, ?, ?);")) {

                stmt.setString(1, userId);
                stmt.setString(2, dataId);
                stmt.setBytes(3, cellKey.getCpk());
                stmt.setBytes(4, cellKey.getEncryptedCskCms());
                stmt.setBytes(5, cellKey.getEncryptedCskBody());

                try {
                    stmt.executeUpdate();
                }
                catch (SQLIntegrityConstraintViolationException e) {
                    if (e.getErrorCode() != 1062) {
                        throw e;
                    }

                    throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
                }
            }
        }
    }

    @Override
    public void updateKey(String userId, String dataId, CellKey cellKey) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("UPDATE virgil_keys " +
                    "SET encrypted_csk_cms=? " +
                    "WHERE user_id=? AND data_id=?;")) {

                stmt.setBytes(1, cellKey.getEncryptedCskCms());
                stmt.setString(2, userId);
                stmt.setString(3, dataId);

                stmt.executeUpdate();
            }
        }
    }

    @Override
    public void deleteKey(String userId, String dataId) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM virgil_keys WHERE user_id = ? AND data_id = ?;")) {
                stmt.setString(1, userId);
                stmt.setString(2, dataId);

                stmt.executeUpdate();
            }
        }
    }

    @Override
    public void insertRole(Role role) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_roles (" +
                    "role_name," +
                    "rpk) " +
                    "VALUES (?, ?);")) {

                stmt.setString(1, role.getRoleName());
                stmt.setBytes(2, role.getRpk());

                stmt.executeUpdate();
            }
        }
    }

    private static Role parseRole(ResultSet rs) throws SQLException {
        return new Role(rs.getString(1), rs.getBytes(2));
    }

    @Override
    public Iterable<Role> selectRoles(Set<String> roleNames) throws Exception {
        if (roleNames.isEmpty()) {
            return new ArrayList<>();
        }

        try (Connection conn = getConnection()) {
            StringBuilder sbSql = new StringBuilder(512);
            sbSql.append("SELECT role_name, rpk " +
                    "FROM virgil_roles " +
                    "WHERE role_name in (");

            for (int i = 0; i < roleNames.size(); i++) {
                if (i > 0) sbSql.append(",");
                sbSql.append("?");
            }
            sbSql.append(");");

            try (PreparedStatement stmt = conn.prepareStatement(sbSql.toString())) {
                int i = 1;
                for (String roleNmae : roleNames) {
                    stmt.setString(i++, roleNmae);
                }

                try (ResultSet rs = stmt.executeQuery()) {
                    ArrayList<Role> roles = new ArrayList<>();
                    while (rs.next()) {
                        roles.add(parseRole(rs));
                    }

                    return roles;
                }
            }
        }
    }

    @Override
    public void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) throws Exception {
        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_role_assignments (" +
                    "role_name," +
                    "user_id," +
                    "public_key_id," +
                    "encrypted_rsk) " +
                    "VALUES (?, ?, ?, ?);")) {

                for (RoleAssignment roleAssignment: roleAssignments) {
                    stmt.setString(1, roleAssignment.getRoleName());
                    stmt.setString(2, roleAssignment.getUserId());
                    stmt.setBytes(3, roleAssignment.getPublicKeyId());
                    stmt.setBytes(4, roleAssignment.getEncryptedRsk());
                    stmt.addBatch();
                }

                stmt.executeBatch();
            }
            finally {
                conn.setAutoCommit(true);
            }
        }
    }

    private static RoleAssignment parseRoleAssignment(ResultSet rs) throws SQLException {
        return new RoleAssignment(rs.getString(1), rs.getString(2), rs.getBytes(3), rs.getBytes(4));
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT role_name, user_id, public_key_id, encrypted_rsk " +
                    "FROM virgil_role_assignments " +
                    "WHERE user_id=?;")) {

                stmt.setString(1, userId);

                try (ResultSet rs = stmt.executeQuery()) {
                    ArrayList<RoleAssignment> roleAssignments = new ArrayList<>();
                    while (rs.next()) {
                        roleAssignments.add(parseRoleAssignment(rs));
                    }

                    return roleAssignments;
                }
            }
        }
    }

    @Override
    public RoleAssignment selectRoleAssignment(String roleName, String userId) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT role_name, user_id, public_key_id, encrypted_rsk " +
                    "FROM virgil_role_assignments " +
                    "WHERE user_id=? AND role_name=?;")) {

                stmt.setString(1, userId);
                stmt.setString(2, roleName);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        return parseRoleAssignment(rs);
                    }
                    else {
                        return null;
                    }
                }
            }
        }
    }

    @Override
    public void deleteRoleAssignments(String roleName, Set<String> userIds) throws Exception {
        if (userIds.isEmpty()) {
            return;
        }

        try (Connection conn = getConnection()) {
            StringBuilder sbSql = new StringBuilder( 512 );
            sbSql.append("DELETE FROM virgil_role_assignments WHERE role_name=? AND user_id in (" );

            for (int i = 0; i < userIds.size(); i++) {
                if (i > 0) sbSql.append(",");
                sbSql.append("?");
            }
            sbSql.append(");");

            try (PreparedStatement stmt = conn.prepareStatement(sbSql.toString())) {
                stmt.setString(1, roleName);

                int i = 2;
                for (String userId: userIds) {
                    stmt.setString(i++, userId);
                }

                stmt.executeUpdate();
            }
        }
    }
}
