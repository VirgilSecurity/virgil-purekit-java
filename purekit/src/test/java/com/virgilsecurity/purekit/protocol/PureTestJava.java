package com.virgilsecurity.purekit.protocol;

import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.pure.*;
import com.virgilsecurity.purekit.utils.PropertyManager;
import com.virgilsecurity.purekit.utils.ThreadUtils;
import com.virgilsecurity.sdk.crypto.KeyType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static com.virgilsecurity.crypto.foundation.FoundationException.ERROR_KEY_RECIPIENT_IS_NOT_FOUND;
import static com.virgilsecurity.crypto.phe.PheException.ERROR_AES_FAILED;
import static org.junit.jupiter.api.Assertions.*;

class PureTestJava {
    static class RamStorage implements PureStorage {

        private HashMap<String, UserRecord> users;
        private HashMap<String, HashMap<String, CellKey>> keys;

        RamStorage() {
            this.users = new HashMap<>();
            this.keys = new HashMap<>();
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
        public UserRecord selectUser(String userId) {
            return this.users.get(userId);
        }

        public static Predicate<UserRecord> isNotVersion(Integer version) {
            return p -> p.getPheRecordVersion() != version;
        }

        @Override
        public Iterable<UserRecord> selectUsers(int pheRecordVersion) {
            Collection<UserRecord> records = this.users.values();
            records.removeIf(isNotVersion(pheRecordVersion));

            List<UserRecord> list = new ArrayList<>(records);

            int limit = 10;

            return list.subList(0, Math.min(limit, list.size()));
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
        public void insertKey(String userId, String dataId, byte[] cpk, byte[] encryptedCskCms, byte[] encryptedCskBody) throws PureStorageKeyAlreadyExistsException {
            HashMap<String, CellKey> map = this.keys.getOrDefault(userId, new HashMap<>());

            CellKey cellKey = new CellKey(cpk, encryptedCskCms, encryptedCskBody);

            if (map.putIfAbsent(dataId, cellKey) != null) {
                throw new PureStorageKeyAlreadyExistsException();
            }

            this.keys.put(userId, map);
        }

        @Override
        public void updateKey(String userId, String dataId, byte[] encryptedCskCms) {
            HashMap<String, CellKey> map = this.keys.get(userId);

            CellKey cellKey = map.get(dataId);

            CellKey newCellKey = new CellKey(cellKey.getCpk(), encryptedCskCms, cellKey.getEncryptedCskBody());

            map.put(dataId, newCellKey);
        }
    }

    private static class PureSetupResult {
        private Pure pure;
        private VirgilKeyPair bupkp;
        private VirgilKeyPair hkp;
        private byte[] ak;

        public PureSetupResult(Pure pure, VirgilKeyPair bupkp, VirgilKeyPair hkp, byte[] ak) {
            this.pure = pure;
            this.bupkp = bupkp;
            this.hkp = hkp;
            this.ak = ak;
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

        public byte[] getAk() {
            return ak;
        }
    }

    private PureSetupResult setupPure(String serverAddress,
                                      String appToken,
                                      String publicKey,
                                      String secretKey) throws CryptoException {
        return this.setupPure(serverAddress, appToken, publicKey, secretKey, null, null);
    }

    private PureSetupResult setupPure(String serverAddress,
                                      String appToken,
                                      String publicKey,
                                      String secretKey,
                                      String updateToken,
                                      PureStorage storage) throws CryptoException {
        VirgilCrypto crypto = new VirgilCrypto();

        VirgilKeyPair bupkp = crypto.generateKeyPair(KeyType.ED25519);
        VirgilKeyPair hkp = crypto.generateKeyPair(KeyType.ED25519);

        byte[] ak = crypto.generateRandomData(32);

        PureContext context = new PureContext(appToken,
                Base64.getEncoder().encodeToString(ak), Base64.getEncoder().encodeToString(crypto.exportPublicKey(bupkp.getPublicKey())),
                Base64.getEncoder().encodeToString(crypto.exportPublicKey(hkp.getPublicKey())), secretKey, publicKey);

        context.setUpdateToken(updateToken);
        context.setServiceAddress(serverAddress);

        if (storage == null) {
            RamStorage ramStorage = new RamStorage();
            context.setStorage(ramStorage);
        }
        else {
            context.setStorage(storage);
        }

        return new PureSetupResult(new Pure(context), bupkp, hkp, ak);
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void register(String serverAddress,
                  String appToken,
                  String publicKey,
                  String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
            Pure pure = pureResult.getPure();

            String userId = UUID.randomUUID().toString();
            String password = UUID.randomUUID().toString();

            pure.registerUser(userId, password);
        }
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void authenticate(String serverAddress,
                      String appToken,
                      String publicKey,
                      String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encrypt_decrypt(String serverAddress,
                         String appToken,
                         String publicKey,
                         String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void share(String serverAddress,
               String appToken,
               String publicKey,
               String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void unshare(String serverAddress,
                 String appToken,
                 String publicKey,
                 String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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

            FoundationException e = assertThrows(FoundationException.class, () -> {
                pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);
            });

            assertEquals(e.getStatusCode(), ERROR_KEY_RECIPIENT_IS_NOT_FOUND);
        }
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encrypt_grant(String serverAddress,
                    String appToken,
                    String publicKey,
                    String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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

            PheException e = assertThrows(PheException.class, () -> {
                PureGrant grant1 = pure.decryptGrantFromUser(authResult1.getEncryptedGrant());
            });

            assertEquals(e.getStatusCode(), ERROR_AES_FAILED);
        }
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void admin_access(String serverAddress,
                      String appToken,
                      String publicKey,
                      String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void reset_pwd(String serverAddress,
                   String appToken,
                   String publicKey,
                   String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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

            FoundationException e = assertThrows(FoundationException.class, () -> {
                byte[] plainText = pure.decrypt(authResult.getGrant(), null, dataId, cipherText);
            });

            assertEquals(e.getStatusCode(), ERROR_KEY_RECIPIENT_IS_NOT_FOUND);
        }
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void restore_pwd(String serverAddress,
                     String appToken,
                     String publicKey,
                     String secretKey) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey);
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
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArguments")
    void rotation(String serverAddress,
                  String appToken,
                  String publicKey,
                  String secretKey,
                  String updateToken) throws InterruptedException, ProtocolException {
        ThreadUtils.pause();

        try {
            RamStorage ramStorage = new RamStorage();

            long total = 30;

            for (long i = 0; i < total;  i++) {
                PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey, null, ramStorage);
                Pure pure = pureResult.getPure();

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);
            }

            PureSetupResult pureResult = this.setupPure(serverAddress, appToken, publicKey, secretKey, updateToken, ramStorage);
            Pure pure = pureResult.getPure();

            long rotated = pure.performRotation();

            assertEquals(total, rotated);
        }
        catch (Exception | ProtocolHttpException e) {
            fail(e);
        }
    }

    private static Stream<Arguments> testArgumentsNoToken() {
        return Stream.of(
                Arguments.of(PropertyManager.getVirgilServerAddress(),
                        PropertyManager.getVirgilAppToken(),
                        PropertyManager.getVirgilPublicKeyNew(),
                        PropertyManager.getVirgilSecretKeyNew())
        );
    }

    private static Stream<Arguments> testArguments() {
        return Stream.of(
                Arguments.of(PropertyManager.getVirgilServerAddress(),
                        PropertyManager.getVirgilAppToken(),
                        PropertyManager.getVirgilPublicKeyNew(),
                        PropertyManager.getVirgilSecretKeyNew(),
                        PropertyManager.getVirgilUpdateTokenNew())
        );
    }
}
