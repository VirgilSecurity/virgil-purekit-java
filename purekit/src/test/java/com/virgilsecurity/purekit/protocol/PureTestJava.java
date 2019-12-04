package com.virgilsecurity.purekit.protocol;

import static com.virgilsecurity.crypto.foundation.FoundationException.ERROR_KEY_RECIPIENT_IS_NOT_FOUND;
import static com.virgilsecurity.crypto.phe.PheException.ERROR_AES_FAILED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.sql.SQLException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.pure.*;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.mariadb.MariaDbPureStorage;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.utils.PropertyManager;
import com.virgilsecurity.purekit.utils.ThreadUtils;
import com.virgilsecurity.sdk.crypto.KeyType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mariadb.jdbc.MariaDbDataSource;

class PureTestJava {
    static class RamStorage implements PureStorage {

        private HashMap<String, UserRecord> users;
        private HashMap<String, HashMap<String, CellKey>> keys;
        private HashMap<String, Role> roles;
        private HashMap<String, HashMap<String, RoleAssignment>> roleAssignments;

        RamStorage() {
            this.users = new HashMap<>();
            this.keys = new HashMap<>();
            this.roles = new HashMap<>();
            this.roleAssignments = new HashMap<>();
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
            return p -> p.getPheRecordVersion() != version;
        }

        @Override
        public Collection<UserRecord> selectUsers(int pheRecordVersion) {
            Collection<UserRecord> records = this.users.values();
            records.removeIf(isNotVersion(pheRecordVersion));

            List<UserRecord> list = new ArrayList<>(records);

            int limit = 10;

            return list.subList(0, Math.min(limit, list.size()));
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
        public CellKey selectKey(String userId, String dataId) {
            HashMap<String, CellKey> map = this.keys.get(userId);

            if (map == null) {
                return null;
            }

            return map.get(dataId);
        }

        @Override
        public void insertKey(String userId, String dataId, CellKey cellKey) throws PureException {
            HashMap<String, CellKey> map = this.keys.getOrDefault(userId, new HashMap<>());

            if (map.putIfAbsent(dataId, cellKey) != null) {
                throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
            }

            this.keys.put(userId, map);
        }

        @Override
        public void updateKey(String userId, String dataId, CellKey cellKey) throws PureException {
            HashMap<String, CellKey> map = this.keys.get(userId);

            if (!map.containsKey(dataId)) {
                throw new PureLogicException(PureLogicException.ErrorStatus.CELL_KEY_ALREADY_EXISTS_IN_STORAGE);
            }

            map.put(dataId, cellKey);
        }

        @Override
        public void deleteKey(String userId, String dataId) {
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
        }
    }

    private static class PureSetupResult {
        private Pure pure;
        private VirgilCrypto crypto;
        private VirgilKeyPair bupkp;
        private VirgilKeyPair hkp;

        public PureSetupResult(Pure pure, VirgilCrypto crypto, VirgilKeyPair bupkp, VirgilKeyPair hkp) {
            this.pure = pure;
            this.crypto = crypto;
            this.bupkp = bupkp;
            this.hkp = hkp;
        }

        public Pure getPure() {
            return pure;
        }

        public VirgilKeyPair getBupkp() {
            return bupkp;
        }

        public VirgilKeyPair getHkp() {
            return hkp;
        }

        public VirgilCrypto getCrypto() {
            return crypto;
        }
    }

    private VirgilCrypto crypto;

    public PureTestJava() {
        this.crypto = new VirgilCrypto();
    }

    private PureSetupResult setupPure(String pheServerAddress,
                                      String pureServerAddress,
                                      String appToken,
                                      String publicKey,
                                      String secretKey,
                                      Map<String, List<String>> externalPublicKeys,
                                      PureStorage storage) throws CryptoException, PureException {
        return this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, externalPublicKeys, storage);
    }

    private PureSetupResult setupPure(String pheServerAddress,
                                      String pureServerAddress,
                                      String appToken,
                                      String publicKey,
                                      String secretKey,
                                      String updateToken,
                                      Map<String, List<String>> externalPublicKeys,
                                      PureStorage storage) throws CryptoException, PureException {
        VirgilKeyPair bupkp = this.crypto.generateKeyPair(KeyType.ED25519);
        VirgilKeyPair hkp = this.crypto.generateKeyPair(KeyType.ED25519);
        VirgilKeyPair oskp = this.crypto.generateKeyPair(KeyType.ED25519);

        byte[] akData = this.crypto.generateRandomData(32);
        String akString = String.format("AK.%s", Base64.getEncoder().encodeToString(akData));

        String bupkpString = String.format("BU.%s", Base64.getEncoder().encodeToString(this.crypto.exportPublicKey(bupkp.getPublicKey())));
        String hkpString = String.format("HB.%s", Base64.getEncoder().encodeToString(this.crypto.exportPublicKey(hkp.getPublicKey())));
        String oskpString = String.format("OS.%s", Base64.getEncoder().encodeToString(this.crypto.exportPrivateKey(oskp.getPrivateKey())));

        PureContext context;
        if (storage != null) {
            context = PureContext.createContext(appToken, akString, bupkpString, hkpString, oskpString,
                    storage, secretKey, publicKey, externalPublicKeys, pheServerAddress);
        } else {
            VirgilKeyPair signingKeyPair = this.crypto.generateKeyPair();
            String vkString = String.format("VS.%s", Base64.getEncoder().encodeToString(this.crypto.exportPrivateKey(signingKeyPair.getPrivateKey())));

            context = PureContext.createContext(appToken, akString, bupkpString, hkpString, oskpString, vkString,
                    secretKey, publicKey, externalPublicKeys, pheServerAddress, pureServerAddress);
        }

        if (updateToken != null) {
            context.setUpdateToken(updateToken);
        }

        return new PureSetupResult(new Pure(context), crypto, bupkp, hkp);
    }

    private static PureStorage[] createStorages() {
        PureStorage[] storages = new PureStorage[1];

//        storages[0] = new RamStorage();
//        storages[1] = null;
        // FIXME
        storages[0] = new MariaDbPureStorage("jdbc:mariadb://localhost/puretest?user=root&password=qwerty");

        return storages;
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void registration__new_user__should_succeed(String pheServerAddress,
                                                String pureServerAddress,
                                                String appToken,
                                                String publicKey,
                                                String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;

            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void authentication__new_user__should_succeed(String pheServerAddress,
                                                  String pureServerAddress,
                                                  String appToken,
                                                  String publicKey,
                                                  String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);

                AuthResult authResult = pure.authenticateUser(userId, password);

                assertNotNull(authResult.getEncryptedGrant());

                PureGrant grant = authResult.getGrant();
                assertNotNull(grant);

                assertEquals(userId, grant.getUserId());
                assertNull(grant.getSessionId());
                assertNotNull(grant.getUkp());
                assertNotNull(grant.getCreationDate());
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__random_data__should_match(String pheServerAddress,
                                               String pureServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                AuthResult authResult = pure.authenticateUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                byte[] plainText = pure.decrypt(authResult.getGrant(), null, dataId, cipherText);

                assertArrayEquals(text, plainText);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void sharing__2_users__should_decrypt(String pheServerAddress,
                                          String pureServerAddress,
                                          String appToken,
                                          String publicKey,
                                          String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId1 = UUID.randomUUID().toString();
                String userId2 = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId1, password1);
                pure.registerUser(userId2, password2);

                AuthResult authResult1 = pure.authenticateUser(userId1, password1);
                AuthResult authResult2 = pure.authenticateUser(userId2, password2);

                byte[] cipherText = pure.encrypt(userId1, dataId, text);

                pure.share(authResult1.getGrant(), dataId, userId2);

                byte[] plainText1 = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                byte[] plainText2 = pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);

                assertArrayEquals(text, plainText1);
                assertArrayEquals(text, plainText2);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void sharing__revoke_access__should_not_decrypt(String pheServerAddress,
                                                    String pureServerAddress,
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId1 = UUID.randomUUID().toString();
                String userId2 = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId1, password1);
                pure.registerUser(userId2, password2);

                AuthResult authResult1 = pure.authenticateUser(userId1, password1);
                AuthResult authResult2 = pure.authenticateUser(userId2, password2);

                byte[] cipherText = pure.encrypt(userId1, dataId, text);

                pure.share(authResult1.getGrant(), dataId, userId2);
                pure.unshare(userId1, dataId, userId2);

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);
                });

                assertEquals(e.getErrorStatus(), PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__change_password__should_not_decrypt(String pheServerAddress,
                                                    String pureServerAddress,
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();

                pure.registerUser(userId, password1);

                AuthResult authResult1 = pure.authenticateUser(userId, password1);

                PureGrant grant = pure.decryptGrantFromUser(authResult1.getEncryptedGrant());

                assertNotNull(grant);

                assertEquals(grant.getSessionId(), authResult1.getGrant().getSessionId());
                assertEquals(grant.getUserId(), authResult1.getGrant().getUserId());
                assertArrayEquals(grant.getUkp().getPrivateKey().getIdentifier(), authResult1.getGrant().getUkp().getPrivateKey().getIdentifier());

                pure.changeUserPassword(userId, password1, password2);

                PureCryptoException ex = assertThrows(PureCryptoException.class, () -> {
                    pure.decryptGrantFromUser(authResult1.getEncryptedGrant());
                });

                assertEquals(ex.getPheException().getStatusCode(), ERROR_AES_FAILED);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__admin_access__should_decrypt(String pheServerAddress,
                                             String pureServerAddress,
                                             String appToken,
                                             String publicKey,
                                             String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                PureGrant adminGrant = pure.createUserGrantAsAdmin(userId, pureResult.getBupkp().getPrivateKey());

                assertNotNull(adminGrant);

                byte[] plainText = pure.decrypt(adminGrant, null, dataId, cipherText);

                assertArrayEquals(text, plainText);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void reset_pwd__new_user__should_not_decrypt(String pheServerAddress,
                                                 String pureServerAddress,
                                                 String appToken,
                                                 String publicKey,
                                                 String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password1);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                pure.resetUserPassword(userId, password2);

                AuthResult authResult = pure.authenticateUser(userId, password2);

                assertNotNull(authResult);

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult.getGrant(), null, dataId, cipherText);
                });

                assertEquals(e.getErrorStatus(), PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void restore_pwd__new_user__should_decrypt(String pheServerAddress,
                                               String pureServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password1);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                PureGrant adminGrant = pure.createUserGrantAsAdmin(userId, pureResult.getBupkp().getPrivateKey());

                pure.changeUserPassword(adminGrant, password2);

                AuthResult authResult = pure.authenticateUser(userId, password2);

                assertNotNull(authResult);

                byte[] plainText = pure.decrypt(authResult.getGrant(), null, dataId, cipherText);

                assertArrayEquals(text, plainText);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArguments")
    void rotation__local_storage__should_rotate(String pheServerAddress,
                                                String pureServerAddress,
                                                String appToken,
                                                String publicKey,
                                                String secretKey,
                                                String updateToken) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                if (storage instanceof VirgilCloudPureStorage) {
                    continue;
                }

                long total = 30;

                for (long i = 0; i < total; i++) {
                    PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
                    Pure pure = pureResult.getPure();

                    String userId = UUID.randomUUID().toString();
                    String password = UUID.randomUUID().toString();

                    pure.registerUser(userId, password);
                }

                PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, updateToken, null, storage);
                Pure pure = pureResult.getPure();

                long rotated = pure.performRotation();

                assertEquals(total, rotated);

                // TODO: Check auth and decryption works
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__additional_keys__should_decrypt(String pheServerAddress,
                                                     String pureServerAddress,
                                                     String appToken,
                                                     String publicKey,
                                                     String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId1 = UUID.randomUUID().toString();
                String userId2 = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId1, password1);
                pure.registerUser(userId2, password2);

                AuthResult authResult1 = pure.authenticateUser(userId1, password1);
                AuthResult authResult2 = pure.authenticateUser(userId2, password2);

                VirgilKeyPair keyPair = pureResult.getCrypto().generateKeyPair();

                byte[] cipherText = pure.encrypt(userId1, dataId, Collections.singleton(userId2), Collections.emptySet(), Collections.singletonList(keyPair.getPublicKey()), text);

                byte[] plainText = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);

                assertArrayEquals(text, plainText);

                plainText = pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);

                assertArrayEquals(text, plainText);

                plainText = pure.decrypt(keyPair.getPrivateKey(), userId1, dataId, cipherText);

                assertArrayEquals(text, plainText);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__external_keys__should_decrypt(String pheServerAddress,
                                                   String pureServerAddress,
                                                   String appToken,
                                                   String publicKey,
                                                   String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                VirgilKeyPair keyPair = this.crypto.generateKeyPair();
                String dataId = UUID.randomUUID().toString();
                String publicKeyBase64 = Base64.getEncoder().encodeToString(crypto.exportPublicKey(keyPair.getPublicKey()));
                Map<String, List<String>> externalPublicKeys = Collections.singletonMap(dataId, Collections.singletonList(publicKeyBase64));

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, externalPublicKeys, storage);

                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                byte[] plainText = pure.decrypt(keyPair.getPrivateKey(), userId, dataId, cipherText);

                assertArrayEquals(text, plainText);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_user__cascade__should_delete_user_and_keys(String pheServerAddress,
                                                           String pureServerAddress,
                                                           String appToken,
                                                           String publicKey,
                                                           String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                AuthResult authResult1 = pure.authenticateUser(userId, password);

                pure.deleteUser(userId, true);

                PureLogicException e1 = assertThrows(PureLogicException.class, () -> {
                    pure.authenticateUser(userId, password);
                });

                assertEquals(PureLogicException.ErrorStatus.USER_NOT_FOUND_IN_STORAGE, e1.getErrorStatus());

                PureLogicException e2 = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                });

                assertEquals(PureLogicException.ErrorStatus.CELL_KEY_NOT_FOUND_IN_STORAGE, e2.getErrorStatus());
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_user__no_cascade__should_delete_user(String pheServerAddress,
                                                     String pureServerAddress,
                                                     String appToken,
                                                     String publicKey,
                                                     String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                // MariaDbPureStorage only supports cascade = true
                if (storage instanceof MariaDbPureStorage) {
                    continue;
                }

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                AuthResult authResult1 = pure.authenticateUser(userId, password);

                pure.deleteUser(userId, false);

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    pure.authenticateUser(userId, password);
                });

                assertEquals(PureLogicException.ErrorStatus.USER_NOT_FOUND_IN_STORAGE, e.getErrorStatus());

                byte[] plainText = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);

                assertArrayEquals(text, plainText);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_key__new_key__should_delete(String pheServerAddress,
                                            String pureServerAddress,
                                            String appToken,
                                            String publicKey,
                                            String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                AuthResult authResult1 = pure.authenticateUser(userId, password);

                pure.deleteKey(userId, dataId);

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    byte[] plainText = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                });

                assertEquals(PureLogicException.ErrorStatus.CELL_KEY_NOT_FOUND_IN_STORAGE, e.getErrorStatus());
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void registration__new_user__backups_pwd_hash(String pheServerAddress,
                                                  String pureServerAddress,
                                                  String appToken,
                                                  String publicKey,
                                                  String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);

                UserRecord record = pure.getStorage().selectUser(userId);

                byte[] pwdHashDecrypted = pureResult.getCrypto().decrypt(record.getEncryptedPwdHash(), pureResult.getHkp().getPrivateKey());
                byte[] pwdHash = pureResult.getCrypto().computeHash(password.getBytes());

                assertArrayEquals(pwdHash, pwdHashDecrypted);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__roles__should_decrypt(String pheServerAddress,
                                           String pureServerAddress,
                                           String appToken,
                                           String publicKey,
                                           String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            PureStorage[] storages = createStorages();
            for (PureStorage storage: storages) {
                // TODO: Remove
                if (storage instanceof VirgilCloudPureStorage) {
                    continue;
                }

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = pureResult.getPure();

                String userId1 = UUID.randomUUID().toString();
                String userId2 = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                String roleName = UUID.randomUUID().toString();

                pure.registerUser(userId1, password1);
                pure.registerUser(userId2, password2);

                byte[] text = UUID.randomUUID().toString().getBytes();

                AuthResult authResult1 = pure.authenticateUser(userId1, password1);
                AuthResult authResult2 = pure.authenticateUser(userId2, password2);

                Set<String> userIds = new HashSet<>();

                userIds.add(userId1);
                userIds.add(userId2);

                pure.createRole(roleName, userIds);

                byte[] cipherText = pure.encrypt(userId1, dataId, Collections.emptySet(), Collections.singleton(roleName), Collections.emptyList(), text);

                byte[] plainText1 = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                byte[] plainText2 = pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);

                assertArrayEquals(text, plainText1);
                assertArrayEquals(text, plainText2);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    private static Stream<Arguments> testArgumentsNoToken() {
        return Stream.of(
            Arguments.of(PropertyManager.getPheServiceAddress(),
                         PropertyManager.getPureServerAddress(),
                         PropertyManager.getAppToken(),
                         PropertyManager.getPublicKeyNew(),
                         PropertyManager.getSecretKeyNew())
        );
    }

    private static Stream<Arguments> testArguments() {
        return Stream.of(
            Arguments.of(PropertyManager.getPheServiceAddress(),
                         PropertyManager.getPureServerAddress(),
                         PropertyManager.getAppToken(),
                         PropertyManager.getPublicKeyOld(),
                         PropertyManager.getSecretKeyOld(),
                         PropertyManager.getUpdateToken())
        );
    }
}
