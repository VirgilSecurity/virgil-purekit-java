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

import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.pure.model.*;

import java.io.IOException;
import java.sql.*;
import java.util.*;

/**
 * MariaDB storage
 */
public class MariaDbPureStorage implements PureStorage, PureModelSerializerDependent {
    private final String url;

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
        this.pureModelSerializer = pureModelSerializer;
    }

    private PureModelSerializer pureModelSerializer;

    /**
     * Constructor
     * @param url connection url with credentials, e.g. "jdbc:mariadb://localhost/puretest?user=root&password=qwerty"
     */
    public MariaDbPureStorage(String url) {
        this.url = url;
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(url);
    }

    @Override
    public void insertUser(UserRecord userRecord) throws PureStorageException {
        PurekitProtosV3Storage.UserRecord protobuf = pureModelSerializer.serializeUserRecord(userRecord);

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_users (" +
                    "user_id," +
                    "phe_record_version," +
                    "protobuf) " +
                    "VALUES (?, ?, ?);")) {

                stmt.setString(1, userRecord.getUserId());
                stmt.setInt(2, userRecord.getRecordVersion());
                stmt.setBytes(3, protobuf.toByteArray());

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void updateUser(UserRecord userRecord) throws PureStorageException {
        PurekitProtosV3Storage.UserRecord protobuf = pureModelSerializer.serializeUserRecord(userRecord);

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("UPDATE virgil_users " +
                    "SET phe_record_version=?," +
                    "protobuf=? " +
                    "WHERE user_id=?;")) {

                stmt.setInt(1, userRecord.getRecordVersion());
                stmt.setBytes(2, protobuf.toByteArray());
                stmt.setString(3, userRecord.getUserId());

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }

    }

    @Override
    public void updateUsers(Iterable<UserRecord> userRecords, int previousPheVersion) throws PureStorageException {
        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement stmt = conn.prepareStatement("UPDATE virgil_users " +
                    "SET phe_record_version=?," +
                    "protobuf=? " +
                    "WHERE user_id=? AND phe_record_version=?;")) {

                for (UserRecord userRecord: userRecords) {
                    PurekitProtosV3Storage.UserRecord protobuf = pureModelSerializer.serializeUserRecord(userRecord);

                    stmt.setInt(1, userRecord.getRecordVersion());
                    stmt.setBytes(2, protobuf.toByteArray());
                    stmt.setString(3, userRecord.getUserId());
                    stmt.setInt(4, previousPheVersion);
                    stmt.addBatch();
                }

                stmt.executeBatch();
            }
            finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    private UserRecord parseUserRecord(ResultSet rs) throws PureStorageException {
        PurekitProtosV3Storage.UserRecord protobuf;
        try {
            protobuf = PurekitProtosV3Storage.UserRecord.parseFrom(rs.getBinaryStream(1));
        } catch (IOException e) {
            throw new MariaDbSqlException(e);
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }

        return pureModelSerializer.parseUserRecord(protobuf);
    }

    @Override
    public UserRecord selectUser(String userId) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT protobuf " +
                    "FROM virgil_users " +
                    "WHERE user_id=?;")) {

                stmt.setString(1, userId);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        UserRecord userRecord = parseUserRecord(rs);
                        if (!userId.equals(userRecord.getUserId())) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
                        }

                        return userRecord;
                    }
                    else {
                        throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_NOT_FOUND_IN_STORAGE);
                    }
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public Iterable<UserRecord> selectUsers(Set<String> userIds) throws PureStorageException {
        if (userIds.isEmpty()) {
            return new ArrayList<>();
        }

        HashSet<String> idsSet = new HashSet<>(userIds);

        try (Connection conn = getConnection()) {
            StringBuilder sbSql = new StringBuilder( 512 );
            sbSql.append("SELECT protobuf " +
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
                        UserRecord userRecord = parseUserRecord(rs);

                        if (!idsSet.contains(userRecord.getUserId())) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
                        }

                        idsSet.remove(userRecord.getUserId());

                        userRecords.add(userRecord);
                    }

                    return userRecords;
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public Iterable<UserRecord> selectUsers(int pheRecordVersion) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT protobuf " +
                    "FROM virgil_users " +
                    "WHERE phe_record_version=? " +
                    "LIMIT 1000;")) {

                stmt.setInt(1, pheRecordVersion);

                try (ResultSet rs = stmt.executeQuery()) {
                    ArrayList<UserRecord> userRecords = new ArrayList<>();
                    while (rs.next()) {
                        UserRecord userRecord = parseUserRecord(rs);

                        if (pheRecordVersion != userRecord.getRecordVersion()) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.PHE_VERSION_MISMATCH);
                        }

                        userRecords.add(userRecord);
                    }

                    return userRecords;
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void deleteUser(String userId, boolean cascade) throws PureStorageException {
        if (!cascade) {
            // FIXME
            throw new NullPointerException();
        }

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM virgil_users WHERE user_id = ?;")) {
                stmt.setString(1, userId);

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    private CellKey parseCellKey(ResultSet rs) throws PureStorageException {
        PurekitProtosV3Storage.CellKey protobuf;
        try {
            protobuf = PurekitProtosV3Storage.CellKey.parseFrom(rs.getBinaryStream(1));
        } catch (IOException e) {
            throw new MariaDbSqlException(e);
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }

        return pureModelSerializer.parseCellKey(protobuf);
    }

    @Override
    public CellKey selectCellKey(String userId, String dataId) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT protobuf " +
                    "FROM virgil_keys " +
                    "WHERE user_id=? AND data_id=?;")) {

                stmt.setString(1, userId);
                stmt.setString(2, dataId);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        CellKey cellKey = parseCellKey(rs);

                        if (!userId.equals(cellKey.getUserId()) || !dataId.equals(cellKey.getDataId())) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.CELL_KEY_ID_MISMATCH);
                        }

                        return cellKey;
                    }
                    else {
                        throw new PureStorageCellKeyNotFoundException();
                    }
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void insertCellKey(CellKey cellKey) throws PureStorageException {
        PurekitProtosV3Storage.CellKey protobuf = pureModelSerializer.serializeCellKey(cellKey);

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_keys (" +
                    "user_id," +
                    "data_id," +
                    "protobuf) " +
                    "VALUES (?, ?, ?);")) {

                stmt.setString(1, cellKey.getUserId());
                stmt.setString(2, cellKey.getDataId());
                stmt.setBytes(3, protobuf.toByteArray());

                try {
                    stmt.executeUpdate();
                }
                catch (SQLIntegrityConstraintViolationException e) {
                    if (e.getErrorCode() != 1062) {
                        throw e;
                    }

                    throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void updateCellKey(CellKey cellKey) throws PureStorageException {
        PurekitProtosV3Storage.CellKey protobuf = pureModelSerializer.serializeCellKey(cellKey);

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("UPDATE virgil_keys " +
                    "SET protobuf=? " +
                    "WHERE user_id=? AND data_id=?;")) {

                stmt.setBytes(1, protobuf.toByteArray());
                stmt.setString(2, cellKey.getUserId());
                stmt.setString(3, cellKey.getDataId());

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void deleteCellKey(String userId, String dataId) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM virgil_keys WHERE user_id = ? AND data_id = ?;")) {
                stmt.setString(1, userId);
                stmt.setString(2, dataId);

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void insertRole(Role role) throws PureStorageException {
        PurekitProtosV3Storage.Role protobuf = pureModelSerializer.serializeRole(role);

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_roles (" +
                    "role_name," +
                    "protobuf) " +
                    "VALUES (?, ?);")) {

                stmt.setString(1, role.getRoleName());
                stmt.setBytes(2, protobuf.toByteArray());

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    private Role parseRole(ResultSet rs) throws PureStorageException {
        PurekitProtosV3Storage.Role protobuf;
        try {
            protobuf = PurekitProtosV3Storage.Role.parseFrom(rs.getBinaryStream(1));
        } catch (IOException e) {
            throw new MariaDbSqlException(e);
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }

        return pureModelSerializer.parseRole(protobuf);
    }

    @Override
    public Iterable<Role> selectRoles(Set<String> roleNames) throws PureStorageException {
        if (roleNames.isEmpty()) {
            return new ArrayList<>();
        }

        HashSet<String> namesSet = new HashSet<>(roleNames);

        try (Connection conn = getConnection()) {
            StringBuilder sbSql = new StringBuilder(512);
            sbSql.append("SELECT protobuf " +
                    "FROM virgil_roles " +
                    "WHERE role_name in (");

            for (int i = 0; i < roleNames.size(); i++) {
                if (i > 0) sbSql.append(",");
                sbSql.append("?");
            }
            sbSql.append(");");

            try (PreparedStatement stmt = conn.prepareStatement(sbSql.toString())) {
                int i = 1;
                for (String roleName : roleNames) {
                    stmt.setString(i++, roleName);
                }

                try (ResultSet rs = stmt.executeQuery()) {
                    ArrayList<Role> roles = new ArrayList<>();
                    while (rs.next()) {
                        Role role = parseRole(rs);

                        if (!namesSet.contains(role.getRoleName())) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.ROLE_NAME_MISMATCH);
                        }

                        namesSet.remove(role.getRoleName());

                        roles.add(role);
                    }

                    return roles;
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void insertRoleAssignments(Collection<RoleAssignment> roleAssignments) throws PureStorageException {
        try (Connection conn = getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_role_assignments (" +
                    "role_name," +
                    "user_id," +
                    "protobuf) " +
                    "VALUES (?, ?, ?);")) {

                for (RoleAssignment roleAssignment: roleAssignments) {
                    PurekitProtosV3Storage.RoleAssignment protobuf = pureModelSerializer.serializeRoleAssignment(roleAssignment);

                    stmt.setString(1, roleAssignment.getRoleName());
                    stmt.setString(2, roleAssignment.getUserId());
                    stmt.setBytes(3, protobuf.toByteArray());
                    stmt.addBatch();
                }

                stmt.executeBatch();
            }
            finally {
                conn.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    private RoleAssignment parseRoleAssignment(ResultSet rs) throws PureStorageException {
        PurekitProtosV3Storage.RoleAssignment protobuf;
        try {
            protobuf = PurekitProtosV3Storage.RoleAssignment.parseFrom(rs.getBinaryStream(1));
        } catch (IOException e) {
            throw new MariaDbSqlException(e);
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }

        return pureModelSerializer.parseRoleAssignment(protobuf);
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT protobuf " +
                    "FROM virgil_role_assignments " +
                    "WHERE user_id=?;")) {

                stmt.setString(1, userId);

                try (ResultSet rs = stmt.executeQuery()) {
                    ArrayList<RoleAssignment> roleAssignments = new ArrayList<>();
                    while (rs.next()) {
                        RoleAssignment roleAssignment = parseRoleAssignment(rs);

                        if (!roleAssignment.getUserId().equals(userId)) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.ROLE_USER_ID_MISMATCH);
                        }

                        roleAssignments.add(roleAssignment);
                    }

                    return roleAssignments;
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public RoleAssignment selectRoleAssignment(String roleName, String userId) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT protobuf " +
                    "FROM virgil_role_assignments " +
                    "WHERE user_id=? AND role_name=?;")) {

                stmt.setString(1, userId);
                stmt.setString(2, roleName);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RoleAssignment roleAssignment = parseRoleAssignment(rs);

                        if (!roleAssignment.getUserId().equals(userId) || !roleAssignment.getRoleName().equals(roleName)) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.ROLE_NAME_USER_ID_MISMATCH);
                        }

                        return roleAssignment;
                    }
                    else {
                        return null;
                    }
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void deleteRoleAssignments(String roleName, Set<String> userIds) throws PureStorageException {
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
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public void insertGrantKey(GrantKey grantKey) throws PureStorageException {
        PurekitProtosV3Storage.GrantKey protobuf = pureModelSerializer.serializeGrantKey(grantKey);

        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("INSERT INTO virgil_grant_keys (" +
                    "user_id," +
                    "key_id," +
                    "expiration_date," +
                    "protobuf) " +
                    "VALUES (?, ?, ?, ?);")) {

                Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
                stmt.setString(1, grantKey.getUserId());
                stmt.setBytes(2, grantKey.getKeyId());
                stmt.setTimestamp(3, new Timestamp(grantKey.getExpirationDate().getTime()), cal);
                stmt.setBytes(4, protobuf.toByteArray());

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    @Override
    public GrantKey selectGrantKey(String userId, byte[] keyId) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT protobuf " +
                    "FROM virgil_grant_keys " +
                    "WHERE user_id=? AND key_id=?;")) {

                stmt.setString(1, userId);
                stmt.setBytes(2, keyId);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        GrantKey grantKey = parseGrantKey(rs);
                        if (!userId.equals(grantKey.getUserId())) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.USER_ID_MISMATCH);
                        }
                        if (!Arrays.equals(keyId, grantKey.getKeyId())) {
                            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.GRANT_KEY_ID_MISMATCH);
                        }

                        return grantKey;
                    }
                    else {
                        throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.GRANT_KEY_NOT_FOUND_IN_STORAGE);
                    }
                }
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    private GrantKey parseGrantKey(ResultSet rs) throws PureStorageException {
        PurekitProtosV3Storage.GrantKey protobuf;
        try {
            protobuf = PurekitProtosV3Storage.GrantKey.parseFrom(rs.getBinaryStream(1));
        } catch (IOException e) {
            throw new MariaDbSqlException(e);
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }

        return pureModelSerializer.parseGrantKey(protobuf);
    }

    @Override
    public void deleteGrantKey(String userId, byte[] keyId) throws PureStorageException {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM virgil_grant_keys WHERE user_id = ? AND key_id = ?;")) {
                stmt.setString(1, userId);
                stmt.setBytes(2, keyId);

                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    /**
     * Drops tables and events
     *
     * @throws SQLException SQLException
     */
    public void cleanDb() throws SQLException {
        try (Connection conn = getConnection()) {
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("DROP TABLE IF EXISTS virgil_grant_keys, virgil_role_assignments, virgil_roles, virgil_keys, virgil_users;");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("DROP EVENT IF EXISTS delete_expired_grant_keys;");
            }
        }
    }

    /**
     * Creates tables and events. Enables event scheduler
     * @param cleanGrantKeysIntervalSeconds Clean old keys event interval in seconds
     *
     * @throws SQLException SQLException
     */
    public void initDb(int cleanGrantKeysIntervalSeconds) throws SQLException {
        try (Connection conn = getConnection()) {
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_users (" +
                        "user_id CHAR(36) NOT NULL PRIMARY KEY," +
                        "phe_record_version INTEGER NOT NULL," +
                        "    INDEX phe_record_version_index(phe_record_version)," +
                        "    UNIQUE INDEX user_id_phe_record_version_index(user_id, phe_record_version)," +
                        "protobuf VARBINARY(2048) NOT NULL" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_keys (" +
                        "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY," +
                        "user_id CHAR(36) NOT NULL," +
                        "    FOREIGN KEY (user_id)" +
                        "        REFERENCES virgil_users(user_id)" +
                        "        ON DELETE CASCADE," +
                        "data_id VARCHAR(128) NOT NULL," +
                        "    UNIQUE INDEX user_id_data_id_index(user_id, data_id)," +
                        "protobuf VARBINARY(32768) NOT NULL /* FIXME Up to 128 recipients */" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_roles (" +
                        "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY," +
                        "role_name VARCHAR(64) NOT NULL," +
                        "    INDEX role_name_index(role_name)," +
                        "protobuf VARBINARY(196) NOT NULL" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_role_assignments (" +
                        "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY," +
                        "role_name VARCHAR(64) NOT NULL," +
                        "    FOREIGN KEY (role_name)" +
                        "        REFERENCES virgil_roles(role_name)" +
                        "        ON DELETE CASCADE," +
                        "user_id CHAR(36) NOT NULL," +
                        "    FOREIGN KEY (user_id)" +
                        "        REFERENCES virgil_users(user_id)" +
                        "        ON DELETE CASCADE," +
                        "    INDEX user_id_index(user_id)," +
                        "    UNIQUE INDEX user_id_role_name_index(user_id, role_name)," +
                        "protobuf VARBINARY(1024) NOT NULL" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_grant_keys (" +
                        "user_id CHAR(36) NOT NULL," +
                        "    FOREIGN KEY (user_id)" +
                        "        REFERENCES virgil_users(user_id)" +
                        "        ON DELETE CASCADE," +
                        "key_id BINARY(64) NOT NULL," +
                        "expiration_date TIMESTAMP NOT NULL," +
                        "    INDEX expiration_date_index(expiration_date)," +
                        "protobuf VARBINARY(1024) NOT NULL," +
                        "    PRIMARY KEY(user_id, key_id)" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("SET @@global.event_scheduler = 1;");
            }
            try (PreparedStatement stmt = conn.prepareStatement("CREATE EVENT delete_expired_grant_keys ON SCHEDULE EVERY ? SECOND" +
                                             "    DO" +
                                             "        DELETE FROM virgil_grant_keys WHERE expiration_date < CURRENT_TIMESTAMP;")) {
                stmt.setInt(1, cleanGrantKeysIntervalSeconds);

                stmt.executeUpdate();
            }
        }
    }
}
