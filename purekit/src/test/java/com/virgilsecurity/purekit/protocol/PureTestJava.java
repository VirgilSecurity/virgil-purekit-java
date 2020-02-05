package com.virgilsecurity.purekit.protocol;

import static com.virgilsecurity.crypto.phe.PheException.ERROR_AES_FAILED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.sql.SQLException;
import java.util.*;
import java.util.stream.Stream;

import com.virgilsecurity.purekit.pure.*;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.storage.*;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.utils.PropertyManager;
import com.virgilsecurity.purekit.utils.ThreadUtils;
import com.virgilsecurity.sdk.crypto.KeyPairType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class PureTestJava {
    private static class PureSetupResult {
        private final PureContext context;
        private final VirgilKeyPair bupkp;
        private final byte[] nmsData;

        public PureSetupResult(PureContext context, VirgilKeyPair bupkp, byte[] nmsData) {
            this.context = context;
            this.bupkp = bupkp;
            this.nmsData = nmsData;
        }

        public PureContext getContext() {
            return context;
        }

        public VirgilKeyPair getBupkp() {
            return bupkp;
        }

        public byte[] getNmsData() {
            return nmsData;
        }
    }

    private VirgilCrypto crypto;

    public PureTestJava() {
        this.crypto = new VirgilCrypto();
    }

    enum StorageType {
        RAM, VirgilCloud, MariaDB
    }

    private PureSetupResult setupPure(String pheServerAddress,
                                      String pureServerAddress,
                                      String kmsServerAddress,
                                      String appToken,
                                      String publicKey,
                                      String secretKey,
                                      Map<String, List<String>> externalPublicKeys,
                                      StorageType storageType) throws CryptoException, PureException, SQLException {
        return setupPure(null, pheServerAddress, pureServerAddress, kmsServerAddress, appToken,
                publicKey, secretKey, null, externalPublicKeys, storageType, false);
    }

    private PureSetupResult setupPure(byte[] nms,
                                      String pheServerAddress,
                                      String pureServerAddress,
                                      String kmsServerAddress,
                                      String appToken,
                                      String publicKey,
                                      String secretKey,
                                      String updateToken,
                                      Map<String, List<String>> externalPublicKeys,
                                      StorageType storageType,
                                      boolean skipClean) throws CryptoException, PureException, SQLException {
        VirgilKeyPair bupkp = this.crypto.generateKeyPair(KeyPairType.ED25519);

        byte[] nmsData = nms;

        if (nmsData == null) {
            nmsData = this.crypto.generateRandomData(32);
        }
        String nmsString = String.format("NM.%s", Base64.getEncoder().encodeToString(nmsData));

        String bupkpString = String.format("BU.%s", Base64.getEncoder().encodeToString(this.crypto.exportPublicKey(bupkp.getPublicKey())));

        PureContext context;

        switch (storageType) {
            case RAM:
                context = PureContext.createContext(appToken, nmsString, bupkpString,
                        new RamPureStorage(), secretKey, publicKey, externalPublicKeys,
                        pheServerAddress, kmsServerAddress);
                break;

            case VirgilCloud:
                context = PureContext.createContext(appToken, nmsString, bupkpString,
                        secretKey, publicKey, externalPublicKeys,
                        pheServerAddress, pureServerAddress, kmsServerAddress);
                break;

            case MariaDB:
                MariaDbPureStorage mariaDbPureStorage = new MariaDbPureStorage("jdbc:mariadb://localhost/puretest?user=root&password=qwerty");
                if (!skipClean) {
                    mariaDbPureStorage.cleanDb();
                    mariaDbPureStorage.initDb(20);
                }
                context = PureContext.createContext(appToken, nmsString, bupkpString,
                        mariaDbPureStorage, secretKey, publicKey, externalPublicKeys,
                        pheServerAddress, kmsServerAddress);
                break;

            default:
                throw new NullPointerException();
        }

        if (updateToken != null) {
            context.setUpdateToken(updateToken);
        }

        return new PureSetupResult(context, bupkp, nmsData);
    }

    private static StorageType[] createStorages() {
        StorageType[] storages = new StorageType[1];

//        storages[0] = StorageType.RAM;
//        storages[1] = StorageType.MariaDB;
        storages[0] = StorageType.VirgilCloud;

        return storages;
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void registration__new_user__should_succeed(String pheServerAddress,
                                                String pureServerAddress,
                                                String kmsServerAddress,
                                                String appToken,
                                                String publicKey,
                                                String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;

            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
                                                String kmsServerAddress,
                                                String appToken,
                                                String publicKey,
                                                String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
                                               String kmsServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
                                          String kmsServerAddress,
                                          String appToken,
                                          String publicKey,
                                          String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
                                                    String kmsServerAddress,
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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

                assertEquals(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA, e.getErrorStatus());
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__change_password__should_not_decrypt(String pheServerAddress,
                                                    String pureServerAddress,
                                                    String kmsServerAddress,
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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

                assertEquals(ERROR_AES_FAILED, ex.getPheException().getStatusCode());
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__expire__should_not_decrypt(String pheServerAddress,
                                           String pureServerAddress,
                                           String kmsServerAddress,
                                           String appToken,
                                           String publicKey,
                                           String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);

                AuthResult authResult = pure.authenticateUser(userId, password, 10);

                PureGrant grant1 = pure.decryptGrantFromUser(authResult.getEncryptedGrant());

                assertNotNull(grant1);

                Thread.sleep(8000);

                PureGrant grant2 = pure.decryptGrantFromUser(authResult.getEncryptedGrant());

                assertNotNull(grant2);

                Thread.sleep(4000);

                PureException ex = assertThrows(PureException.class, () -> {
                    pure.decryptGrantFromUser(authResult.getEncryptedGrant());
                });

                if (ex instanceof PureLogicException) {
                    assertEquals(PureLogicException.ErrorStatus.GRANT_IS_EXPIRED, ((PureLogicException)(ex)).getErrorStatus());
                }
                else if (ex instanceof PureStorageGenericException) {
                    assertEquals(PureStorageGenericException.ErrorStatus.GRANT_KEY_NOT_FOUND, ((PureStorageGenericException)(ex)).getErrorStatus());
                }
                else {
                    assertEquals(0, 1);
                }
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__admin_access__should_decrypt(String pheServerAddress,
                                             String pureServerAddress,
                                             String kmsServerAddress,
                                             String appToken,
                                             String publicKey,
                                             String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
                                                 String kmsServerAddress,
                                                 String appToken,
                                                 String publicKey,
                                                 String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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

                assertEquals(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA, e.getErrorStatus());
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void restore_pwd__new_user__should_decrypt(String pheServerAddress,
                                               String pureServerAddress,
                                               String kmsServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
                                                String kmsServerAddress,
                                                String appToken,
                                                String publicKeyOld,
                                                String secretKeyOld,
                                                String updateToken,
                                                String publicKeyNew,
                                                String secretKeyNew) throws InterruptedException {
        ThreadUtils.pause();

        try {
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                // VirgilCloudPureStorage should not support that
                if (storage == StorageType.VirgilCloud) {
                    continue;
                }

                long total = 30;

                PureStorage pureStorage;

                String firstUserId = null;
                String firstUserPwd = null;
                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();
                String newPwd = UUID.randomUUID().toString();

                byte[] blob;
                byte[] nms;

                {
                    PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKeyOld, secretKeyOld,  null, storage);
                    Pure pure = new Pure(pureResult.getContext());
                    pureStorage = pure.getStorage();
                    nms = pureResult.getNmsData();

                    for (long i = 0; i < total; i++) {
                        String userId = UUID.randomUUID().toString();
                        String password = UUID.randomUUID().toString();

                        pure.registerUser(userId, password);

                        if (i == 0) {
                            firstUserId = userId;
                            firstUserPwd = password;
                        }
                    }
                }

                {
                    PureSetupResult pureResult = this.setupPure(nms, pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKeyOld, secretKeyOld, updateToken, null, storage, true);
                    pureResult.getContext().setStorage(pureStorage);
                    Pure pure = new Pure(pureResult.getContext());

                    blob = pure.encrypt(firstUserId, dataId, text);

                    long rotated = pure.performRotation();

                    assertEquals(total, rotated);
                }

                {
                    PureSetupResult pureResult = this.setupPure(nms, pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKeyNew, secretKeyNew, null, null, storage, true);
                    pureResult.getContext().setStorage(pureStorage);
                    Pure pure = new Pure(pureResult.getContext());

                    AuthResult authResult = pure.authenticateUser(firstUserId, firstUserPwd);

                    byte[] decrypted = pure.decrypt(authResult.getGrant(), firstUserId, dataId, blob);

                    assertArrayEquals(text, decrypted);

                    pure.recoverUser(firstUserId, newPwd);

                    AuthResult authResult2 = pure.authenticateUser(firstUserId, newPwd);

                    byte[] decrypted2 = pure.decrypt(authResult2.getGrant(), firstUserId, dataId, blob);

                    assertArrayEquals(text, decrypted2);
                }

                {
                    PureSetupResult pureResult = this.setupPure(nms, pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKeyOld, secretKeyOld, updateToken, null, storage, true);
                    pureResult.getContext().setStorage(pureStorage);
                    Pure pure = new Pure(pureResult.getContext());

                    AuthResult authResult = pure.authenticateUser(firstUserId, newPwd);

                    byte[] decrypted = pure.decrypt(authResult.getGrant(), firstUserId, dataId, blob);

                    assertArrayEquals(text, decrypted);

                    String newPwd2 = UUID.randomUUID().toString();

                    pure.recoverUser(firstUserId, newPwd2);

                    AuthResult authResult2 = pure.authenticateUser(firstUserId, newPwd2);

                    byte[] decrypted2 = pure.decrypt(authResult2.getGrant(), firstUserId, dataId, blob);

                    assertArrayEquals(text, decrypted2);
                }
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__additional_keys__should_decrypt(String pheServerAddress,
                                                     String pureServerAddress,
                                                     String kmsServerAddress,
                                                     String appToken,
                                                     String publicKey,
                                                     String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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

                VirgilKeyPair keyPair = pureResult.getContext().getCrypto().generateKeyPair();

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
                                                   String kmsServerAddress,
                                                   String appToken,
                                                   String publicKey,
                                                   String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                VirgilKeyPair keyPair = this.crypto.generateKeyPair();
                String dataId = UUID.randomUUID().toString();
                String publicKeyBase64 = Base64.getEncoder().encodeToString(crypto.exportPublicKey(keyPair.getPublicKey()));
                Map<String, List<String>> externalPublicKeys = Collections.singletonMap(dataId, Collections.singletonList(publicKeyBase64));

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, externalPublicKeys, storage);

                Pure pure = new Pure(pureResult.getContext());

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
                                                           String kmsServerAddress,
                                                           String appToken,
                                                           String publicKey,
                                                           String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                AuthResult authResult1 = pure.authenticateUser(userId, password);

                pure.deleteUser(userId, true);

                PureStorageGenericException e1 = assertThrows(PureStorageGenericException.class, () -> {
                    pure.authenticateUser(userId, password);
                });

                assertEquals(PureStorageGenericException.ErrorStatus.USER_NOT_FOUND, e1.getErrorStatus());

                assertThrows(PureStorageCellKeyNotFoundException.class, () -> {
                    pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                });
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_user__no_cascade__should_delete_user(String pheServerAddress,
                                                     String pureServerAddress,
                                                     String kmsServerAddress,
                                                     String appToken,
                                                     String publicKey,
                                                     String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                // MariaDbPureStorage only supports cascade = true
                if (storage == StorageType.MariaDB) {
                    continue;
                }

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                AuthResult authResult1 = pure.authenticateUser(userId, password);

                pure.deleteUser(userId, false);

                PureStorageGenericException e = assertThrows(PureStorageGenericException.class, () -> {
                    pure.authenticateUser(userId, password);
                });

                assertEquals(PureStorageGenericException.ErrorStatus.USER_NOT_FOUND, e.getErrorStatus());

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
                                            String kmsServerAddress,
                                            String appToken,
                                            String publicKey,
                                            String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                AuthResult authResult1 = pure.authenticateUser(userId, password);

                pure.deleteKey(userId, dataId);

                assertThrows(PureStorageCellKeyNotFoundException.class, () -> {
                    pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                });
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void registration__new_user__backups_pwd_hash(String pheServerAddress,
                                                  String pureServerAddress,
                                                  String kmsServerAddress,
                                                  String appToken,
                                                  String publicKey,
                                                  String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);

                UserRecord record = pure.getStorage().selectUser(userId);

                byte[] pwdHashDecrypted = pureResult.getContext().getCrypto().decrypt(record.getBackupPwdHash(), pureResult.getBupkp().getPrivateKey());
                byte[] pwdHash = pureResult.getContext().getCrypto().computeHash(password.getBytes());

                assertArrayEquals(pwdHash, pwdHashDecrypted);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__roles__should_decrypt(String pheServerAddress,
                                           String pureServerAddress,
                                           String kmsServerAddress,
                                           String appToken,
                                           String publicKey,
                                           String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId1 = UUID.randomUUID().toString();
                String userId2 = UUID.randomUUID().toString();
                String userId3 = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();
                String password3 = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();
                String roleName = UUID.randomUUID().toString();

                pure.registerUser(userId1, password1);
                pure.registerUser(userId2, password2);
                pure.registerUser(userId3, password3);

                byte[] text = UUID.randomUUID().toString().getBytes();

                AuthResult authResult1 = pure.authenticateUser(userId1, password1);
                AuthResult authResult2 = pure.authenticateUser(userId2, password2);
                AuthResult authResult3 = pure.authenticateUser(userId3, password3);

                Set<String> userIds = new HashSet<>();

                userIds.add(userId1);
                userIds.add(userId2);

                pure.createRole(roleName, userIds);

                byte[] cipherText = pure.encrypt(userId1, dataId, Collections.emptySet(), Collections.singleton(roleName), Collections.emptyList(), text);

                byte[] plainText11 = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                byte[] plainText21 = pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);
                assertArrayEquals(text, plainText11);
                assertArrayEquals(text, plainText21);

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult3.getGrant(), userId1, dataId, cipherText);
                });

                assertEquals(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA, e.getErrorStatus());

                pure.assignRole(roleName, authResult2.getGrant(), Collections.singleton(userId3));
                pure.unassignRole(roleName, Collections.singleton(userId1));
                pure.unassignRole(roleName, Collections.singleton(userId2));

                byte[] plainText12 = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                byte[] plainText32 = pure.decrypt(authResult3.getGrant(), userId1, dataId, cipherText);

                assertArrayEquals(text, plainText12);
                assertArrayEquals(text, plainText32);

                e = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);
                });

                assertEquals(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA, e.getErrorStatus());

                pure.assignRole(roleName, authResult3.getGrant(), Collections.singleton(userId2));

                byte[] plainText23 = pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);
                assertArrayEquals(text, plainText23);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void recovery__new_user__should_recover(String pheServerAddress,
                                            String pureServerAddress,
                                            String kmsServerAddress,
                                            String appToken,
                                            String publicKey,
                                            String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password1 = UUID.randomUUID().toString();
                String password2 = UUID.randomUUID().toString();

                pure.registerUser(userId, password1);

                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                byte[] blob = pure.encrypt(userId, dataId, text);

                pure.recoverUser(userId, password2);

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    pure.authenticateUser(userId, password1);
                });

                assertEquals(PureLogicException.ErrorStatus.INVALID_PASSWORD, e.getErrorStatus());

                AuthResult authResult = pure.authenticateUser(userId, password2);
                assertNotNull(authResult);

                byte[] decrypted = pure.decrypt(authResult.getGrant(), userId, dataId, blob);
                assertArrayEquals(text, decrypted);
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    private static Stream<Arguments> testArgumentsNoToken() {
        return Stream.of(
            Arguments.of(PropertyManager.getPheServiceAddress(),
                         PropertyManager.getPureServerAddress(),
                         PropertyManager.getKmsServerAddress(),
                         PropertyManager.getAppToken(),
                         PropertyManager.getPublicKeyNew(),
                         PropertyManager.getSecretKeyNew())
        );
    }

    private static Stream<Arguments> testArguments() {
        return Stream.of(
            Arguments.of(PropertyManager.getPheServiceAddress(),
                         PropertyManager.getPureServerAddress(),
                         PropertyManager.getKmsServerAddress(),
                         PropertyManager.getAppToken(),
                         PropertyManager.getPublicKeyOld(),
                         PropertyManager.getSecretKeyOld(),
                         PropertyManager.getUpdateToken(),
                         PropertyManager.getPublicKeyNew(),
                         PropertyManager.getSecretKeyNew())
        );
    }
}
