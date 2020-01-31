package com.virgilsecurity.purekit.pure.mariadbstorage;

import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.pure.PureModelSerializer;
import com.virgilsecurity.purekit.pure.PureModelSerializerDependent;
import com.virgilsecurity.purekit.pure.PureStorage;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.*;

import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

import javax.swing.plaf.nimbus.State;
import java.io.IOException;
import java.sql.*;
import java.util.*;
import java.util.Date;

public class MariaDbPureStorage implements PureStorage, PureModelSerializerDependent {
    private final String url;

    @Override
    public PureModelSerializer getPureModelSerializer() {
        return pureModelSerializer;
    }

    @Override
    public void setPureModelSerializer(PureModelSerializer pureModelSerializer) {
        this.pureModelSerializer = pureModelSerializer;
    }

    private PureModelSerializer pureModelSerializer;

    public MariaDbPureStorage(String url) {
        this.url = url;
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(url);
    }

    @Override
    public void insertUser(UserRecord userRecord) throws Exception {
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
        }
    }

    @Override
    public void updateUser(UserRecord userRecord) throws Exception {
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
        }
    }

    @Override
    public void updateUsers(Iterable<UserRecord> userRecords, int previousPheVersion) throws Exception {
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
        }
    }

    private UserRecord parseUserRecord(ResultSet rs) throws SQLException, IOException, PureLogicException, VerificationException {
        PurekitProtosV3Storage.UserRecord protobuf =
                PurekitProtosV3Storage.UserRecord.parseFrom(rs.getBinaryStream(1));

        return pureModelSerializer.parseUserRecord(protobuf);
    }

    @Override
    public UserRecord selectUser(String userId) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("SELECT protobuf " +
                    "FROM virgil_users " +
                    "WHERE user_id=?;")) {

                stmt.setString(1, userId);

                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        UserRecord userRecord = parseUserRecord(rs);
                        if (!userId.equals(userRecord.getUserId())) {
                            throw new PureLogicException(PureLogicException.ErrorStatus.USER_ID_MISMATCH);
                        }

                        return userRecord;
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
                            throw new PureLogicException(PureLogicException.ErrorStatus.USER_ID_MISMATCH);
                        }

                        idsSet.remove(userRecord.getUserId());

                        userRecords.add(userRecord);
                    }

                    return userRecords;
                }
            }
        }
    }

    @Override
    public Iterable<UserRecord> selectUsers(int pheRecordVersion) throws Exception {
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
                            throw new PureLogicException(PureLogicException.ErrorStatus.PHE_VERSION_MISMATCH);
                        }

                        userRecords.add(userRecord);
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

    private CellKey parseCellKey(ResultSet rs) throws SQLException, IOException, PureLogicException, VerificationException {
        PurekitProtosV3Storage.CellKey protobuf =
                PurekitProtosV3Storage.CellKey.parseFrom(rs.getBinaryStream(1));

        return pureModelSerializer.parseCellKey(protobuf);
    }

    @Override
    public CellKey selectCellKey(String userId, String dataId) throws Exception {
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
                            throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_ID_MISMATCH);
                        }

                        return cellKey;
                    }
                    else {
                        return null;
                    }
                }
            }
        }
    }

    @Override
    public void insertCellKey(CellKey cellKey) throws Exception {
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

                    throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
                }
            }
        }
    }

    @Override
    public void updateCellKey(CellKey cellKey) throws Exception {
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
        }
    }

    @Override
    public void deleteCellKey(String userId, String dataId) throws Exception {
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
        }
    }

    private Role parseRole(ResultSet rs) throws SQLException, IOException, PureLogicException, VerificationException {
        PurekitProtosV3Storage.Role protobuf =
                PurekitProtosV3Storage.Role.parseFrom(rs.getBinaryStream(1));

        return pureModelSerializer.parseRole(protobuf);
    }

    @Override
    public Iterable<Role> selectRoles(Set<String> roleNames) throws Exception {
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
                            throw new PureLogicException(PureLogicException.ErrorStatus.ROLE_NAME_MISMATCH);
                        }

                        namesSet.remove(role.getRoleName());

                        roles.add(role);
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
        }
    }

    private RoleAssignment parseRoleAssignment(ResultSet rs) throws SQLException, IOException, PureLogicException, VerificationException {
        PurekitProtosV3Storage.RoleAssignment protobuf =
                PurekitProtosV3Storage.RoleAssignment.parseFrom(rs.getBinaryStream(1));

        return pureModelSerializer.parseRoleAssignment(protobuf);
    }

    @Override
    public Iterable<RoleAssignment> selectRoleAssignments(String userId) throws Exception {
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
                            throw new PureLogicException(PureLogicException.ErrorStatus.ROLE_USER_ID_MISMATCH);
                        }

                        roleAssignments.add(roleAssignment);
                    }

                    return roleAssignments;
                }
            }
        }
    }

    @Override
    public RoleAssignment selectRoleAssignment(String roleName, String userId) throws Exception {
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
                            throw new PureLogicException(PureLogicException.ErrorStatus.ROLE_NAME_USER_ID_MISMATCH);
                        }

                        return roleAssignment;
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

    @Override
    public void insertGrantKey(GrantKey grantKey) throws Exception {
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
        }
    }

    @Override
    public GrantKey selectGrantKey(String userId, byte[] keyId) throws Exception {
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
                            throw new PureLogicException(PureLogicException.ErrorStatus.USER_ID_MISMATCH);
                        }
                        if (!Arrays.equals(keyId, grantKey.getKeyId())) {
                            throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_KEY_ID_MISMATCH);
                        }

                        return grantKey;
                    }
                    else {
                        throw new PureLogicException(PureLogicException.ErrorStatus.GRANT_KEY_NOT_FOUND_IN_STORAGE);
                    }
                }
            }
        }
    }

    private GrantKey parseGrantKey(ResultSet rs) throws SQLException, IOException, PureLogicException, VerificationException {
        PurekitProtosV3Storage.GrantKey protobuf =
                PurekitProtosV3Storage.GrantKey.parseFrom(rs.getBinaryStream(1));

        return pureModelSerializer.parseGrantKey(protobuf);
    }

    @Override
    public void deleteGrantKey(String userId, byte[] keyId) throws Exception {
        try (Connection conn = getConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement("DELETE FROM virgil_grant_keys WHERE user_id = ? AND key_id = ?;")) {
                stmt.setString(1, userId);
                stmt.setBytes(2, keyId);

                stmt.executeUpdate();
            }
        }
    }

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

    public void initDb(int cleanGrantKeysIntervalSeconds) throws SQLException {
        try (Connection conn = getConnection()) {
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_users (\n" +
                        "    user_id CHAR(36) NOT NULL PRIMARY KEY,\n" +
                        "    phe_record_version INTEGER NOT NULL,\n" +
                        "    INDEX phe_record_version_index(phe_record_version),\n" +
                        "    UNIQUE INDEX user_id_phe_record_version_index(user_id, phe_record_version),\n" +
                        "    protobuf VARBINARY(2048) NOT NULL\n" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_keys(\n" +
                        "\tid INT NOT NULL AUTO_INCREMENT PRIMARY KEY,\n" +
                        "    user_id CHAR(36) NOT NULL,\n" +
                        "    FOREIGN KEY (user_id)\n" +
                        "\t\tREFERENCES virgil_users(user_id)\n" +
                        "        ON DELETE CASCADE,\n" +
                        "\tdata_id VARCHAR(128) NOT NULL,\n" +
                        "    UNIQUE INDEX user_id_data_id_index(user_id, data_id),\n" +
                        "    protobuf VARBINARY(32768) NOT NULL /* FIXME Up to 128 recipients */\n" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_roles (\n" +
                        "\tid INT NOT NULL AUTO_INCREMENT PRIMARY KEY,\n" +
                        "    role_name VARCHAR(64) NOT NULL,\n" +
                        "    INDEX role_name_index(role_name),\n" +
                        "    protobuf VARBINARY(196) NOT NULL\n" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_role_assignments (\n" +
                        "\tid INT NOT NULL AUTO_INCREMENT PRIMARY KEY,\n" +
                        "    role_name VARCHAR(64) NOT NULL,\n" +
                        "    FOREIGN KEY (role_name)\n" +
                        "\t\tREFERENCES virgil_roles(role_name)\n" +
                        "        ON DELETE CASCADE,\n" +
                        "    user_id CHAR(36) NOT NULL,\n" +
                        "    FOREIGN KEY (user_id)\n" +
                        "\t\tREFERENCES virgil_users(user_id)\n" +
                        "        ON DELETE CASCADE,\n" +
                        "    INDEX user_id_index(user_id),\n" +
                        "    UNIQUE INDEX user_id_role_name_index(user_id, role_name),\n" +
                        "    protobuf VARBINARY(1024) NOT NULL\n" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("CREATE TABLE virgil_grant_keys (\n" +
                        "    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,\n" +
                        "    user_id CHAR(36) NOT NULL,\n" +
                        "    FOREIGN KEY (user_id)\n" +
                        "        REFERENCES virgil_users(user_id)\n" +
                        "        ON DELETE CASCADE,\n" +
                        "    key_id BINARY(64) NOT NULL,\n" +
                        "    expiration_date TIMESTAMP NOT NULL,\n" +
                        "    protobuf VARBINARY(1024) NOT NULL\n" +
                        ");");
            }
            try (Statement stmt = conn.createStatement()) {
                stmt.executeUpdate("SET @@global.event_scheduler = 1;");
            }
            try (PreparedStatement stmt = conn.prepareStatement("CREATE EVENT delete_expired_grant_keys ON SCHEDULE EVERY ? SECOND\n" +
                                             "DO\n" +
                                             "    DELETE FROM virgil_grant_keys WHERE expiration_date < CURRENT_TIMESTAMP;")) {
                stmt.setInt(1, cleanGrantKeysIntervalSeconds);

                stmt.executeUpdate();
            }
        }
    }
}
