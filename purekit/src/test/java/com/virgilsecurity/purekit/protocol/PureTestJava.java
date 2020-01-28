package com.virgilsecurity.purekit.protocol;

import static com.virgilsecurity.crypto.phe.PheException.ERROR_AES_FAILED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.*;
import java.util.stream.Stream;

import com.virgilsecurity.purekit.pure.*;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.mariadbstorage.MariaDbPureStorage;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.pure.ramstorage.RamPureStorage;
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
        private PureContext context;
        private VirgilKeyPair bupkp;

        public PureSetupResult(PureContext context, VirgilKeyPair bupkp) {
            this.context = context;
            this.bupkp = bupkp;
        }

        public PureContext getContext() {
            return context;
        }

        public VirgilKeyPair getBupkp() {
            return bupkp;
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
                                      String updateToken,
                                      Map<String, List<String>> externalPublicKeys,
                                      StorageType storageType) throws CryptoException, PureLogicException {
        VirgilKeyPair bupkp = this.crypto.generateKeyPair(KeyPairType.ED25519);

        byte[] nmsData = this.crypto.generateRandomData(32);
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
                PureStorage mariaDbPureStorage = new MariaDbPureStorage("jdbc:mariadb://localhost/puretest?user=root&password=qwerty");
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

        return new PureSetupResult(context, bupkp);
    }

    private static StorageType[] createStorages() {
        StorageType[] storages = new StorageType[1];

        storages[0] = StorageType.RAM;
//        storages[0] = StorageType.VirgilCloud;
//        storages[0] = StorageType.MariaDB;

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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null,null, storage);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                assertEquals(e.getErrorStatus(), PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                assertEquals(ex.getPheException().getStatusCode(), ERROR_AES_FAILED);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                assertEquals(e.getErrorStatus(), PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                                String publicKey,
                                                String secretKey,
                                                String updateToken) throws InterruptedException {
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

                {
                    PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey,  null,null, storage);
                    Pure pure = new Pure(pureResult.getContext());
                    pureStorage = pure.getStorage();

                    if (storage == StorageType.MariaDB) {
                        MariaDbPureStorage mariaDbPureStorage = (MariaDbPureStorage)pure.getStorage();
                        mariaDbPureStorage.dropTables();
                        mariaDbPureStorage.createTables();
                    }

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

                PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, updateToken,null, storage);
                pureResult.getContext().setStorage(pureStorage);
                Pure pure = new Pure(pureResult.getContext());

                String dataId = UUID.randomUUID().toString();
                byte[] text = UUID.randomUUID().toString().getBytes();

                byte[] blob = pure.encrypt(firstUserId, dataId, text);

                long rotated = pure.performRotation();

                assertEquals(total, rotated);

                AuthResult authResult = pure.authenticateUser(firstUserId, firstUserPwd);

                byte[] decrypted = pure.decrypt(authResult.getGrant(), firstUserId, dataId, blob);

                assertArrayEquals(text, decrypted);

                String newPwd = UUID.randomUUID().toString();

                pure.recoverUser(firstUserId, newPwd);

                AuthResult authResult2 = pure.authenticateUser(firstUserId, newPwd);

                byte[] decrypted2 = pure.decrypt(authResult2.getGrant(), firstUserId, dataId, blob);

                assertArrayEquals(text, decrypted2);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                VirgilKeyPair keyPair = pure.getCrypto().generateKeyPair();

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

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey,null, externalPublicKeys, storage);

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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
                                            String kmsServerAddress,
                                            String appToken,
                                            String publicKey,
                                            String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();
                String dataId = UUID.randomUUID().toString();

                byte[] text = UUID.randomUUID().toString().getBytes();

                pure.registerUser(userId, password);

                byte[] cipherText = pure.encrypt(userId, dataId, text);

                AuthResult authResult1 = pure.authenticateUser(userId, password);

                pure.deleteKey(userId, dataId);

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
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
                                                  String kmsServerAddress,
                                                  String appToken,
                                                  String publicKey,
                                                  String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);

                UserRecord record = pure.getStorage().selectUser(userId);

                byte[] pwdHashDecrypted = pure.getCrypto().decrypt(record.getBackupPwdHash(), pureResult.getBupkp().getPrivateKey());
                byte[] pwdHash = pure.getCrypto().computeHash(password.getBytes());

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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                PureLogicException e = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult3.getGrant(), userId1, dataId, cipherText);
                });

                assertEquals(e.getErrorStatus(), PureLogicException.ErrorStatus.INVALID_PASSWORD);

                assertArrayEquals(text, plainText11);
                assertArrayEquals(text, plainText21);

                pure.unassignRole(roleName, Collections.singleton(userId1));
                pure.assignRole(roleName, authResult2.getGrant(), Collections.singleton(userId3));

                e = assertThrows(PureLogicException.class, () -> {
                    pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
                });

                assertEquals(e.getErrorStatus(), PureLogicException.ErrorStatus.INVALID_PASSWORD);

                byte[] plainText22 = pure.decrypt(authResult2.getGrant(), userId1, dataId, cipherText);
                byte[] plainText32 = pure.decrypt(authResult3.getGrant(), userId1, dataId, cipherText);

                assertArrayEquals(text, plainText22);
                assertArrayEquals(text, plainText32);
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
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                assertEquals(e.getErrorStatus(), PureLogicException.ErrorStatus.INVALID_PASSWORD);

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
                         PropertyManager.getUpdateToken())
        );
    }
}
