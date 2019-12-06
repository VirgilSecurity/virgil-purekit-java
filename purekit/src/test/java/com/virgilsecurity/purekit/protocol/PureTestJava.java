package com.virgilsecurity.purekit.protocol;

import static com.virgilsecurity.crypto.phe.PheException.ERROR_AES_FAILED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.virgilsecurity.purekit.pure.*;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.mariadbstorage.MariaDbPureStorage;
import com.virgilsecurity.purekit.pure.model.*;
import com.virgilsecurity.purekit.pure.ramstorage.RamPureStorage;
import com.virgilsecurity.purekit.utils.PropertyManager;
import com.virgilsecurity.purekit.utils.ThreadUtils;
import com.virgilsecurity.sdk.crypto.KeyType;
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
        private VirgilKeyPair hkp;

        public PureSetupResult(PureContext context, VirgilKeyPair bupkp, VirgilKeyPair hkp) {
            this.context = context;
            this.bupkp = bupkp;
            this.hkp = hkp;
        }

        public PureContext getContext() {
            return context;
        }

        public VirgilKeyPair getBupkp() {
            return bupkp;
        }

        public VirgilKeyPair getHkp() {
            return hkp;
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
                                      String appToken,
                                      String publicKey,
                                      String secretKey,
                                      String updateToken,
                                      Map<String, List<String>> externalPublicKeys,
                                      StorageType storageType) throws CryptoException, PureLogicException {
        VirgilKeyPair bupkp = this.crypto.generateKeyPair(KeyType.ED25519);
        VirgilKeyPair hkp = this.crypto.generateKeyPair(KeyType.ED25519);
        VirgilKeyPair oskp = this.crypto.generateKeyPair(KeyType.ED25519);

        byte[] akData = this.crypto.generateRandomData(32);
        String akString = String.format("AK.%s", Base64.getEncoder().encodeToString(akData));

        String bupkpString = String.format("BU.%s", Base64.getEncoder().encodeToString(this.crypto.exportPublicKey(bupkp.getPublicKey())));
        String hkpString = String.format("HB.%s", Base64.getEncoder().encodeToString(this.crypto.exportPublicKey(hkp.getPublicKey())));
        String oskpString = String.format("OS.%s", Base64.getEncoder().encodeToString(this.crypto.exportPrivateKey(oskp.getPrivateKey())));

        PureContext context;
        VirgilKeyPair signingKeyPair = this.crypto.generateKeyPair();
        String vsString = String.format("VS.%s", Base64.getEncoder().encodeToString(this.crypto.exportPrivateKey(signingKeyPair.getPrivateKey())));

        switch (storageType) {
            case RAM:
                context = PureContext.createContext(appToken, akString, bupkpString, hkpString, oskpString,
                        new RamPureStorage(), secretKey, publicKey, externalPublicKeys, pheServerAddress);
                break;

            case VirgilCloud:
                context = PureContext.createContext(appToken, akString, bupkpString, hkpString, oskpString, vsString,
                        secretKey, publicKey, externalPublicKeys, pheServerAddress, pureServerAddress);
                break;

            case MariaDB:
                PureModelSerializer pureModelSerializer = new PureModelSerializer(this.crypto, signingKeyPair);
                PureStorage mariaDbPureStorage = new MariaDbPureStorage("jdbc:mariadb://localhost/puretest?user=root&password=qwerty", pureModelSerializer);
                context = PureContext.createContext(appToken, akString, bupkpString, hkpString, oskpString,
                        mariaDbPureStorage, secretKey, publicKey, externalPublicKeys, pheServerAddress);
                break;

            default:
                throw new NullPointerException();
        }

        if (updateToken != null) {
            context.setUpdateToken(updateToken);
        }

        return new PureSetupResult(context, bupkp, hkp);
    }

    private static StorageType[] createStorages() {
        StorageType[] storages = new StorageType[1];

//        storages[0] = StorageType.RAM;
//        storages[1] = StorageType.VirgilCloud;
        storages[0] = StorageType.MariaDB;

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

            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                                  String appToken,
                                                  String publicKey,
                                                  String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                          String appToken,
                                          String publicKey,
                                          String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                             String appToken,
                                             String publicKey,
                                             String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                                 String appToken,
                                                 String publicKey,
                                                 String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                {
                    PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                    }
                }

                PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, updateToken, null, storage);
                pureResult.getContext().setStorage(pureStorage);
                Pure pure = new Pure(pureResult.getContext());

                long rotated = pure.performRotation();

                assertEquals(total, rotated);

                // TODO: Check auth and decryption works
            }
        } catch (Exception e) {
            fail(e);
        }
    }

    @ParameterizedTest @MethodSource("testArguments")
    void performance(String pheServerAddress,
                     String pureServerAddress,
                     String appToken,
                     String publicKey,
                     String secretKey,
                     String updateToken) throws InterruptedException {
        ThreadUtils.pause();

        try {
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                if (storage == StorageType.VirgilCloud) {
                    continue;
                }

                PureSetupResult pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                long startTime = System.currentTimeMillis();

                long total = 1;
                for (long i = 0; i < total; i++) {
                    String userId = UUID.randomUUID().toString();
                    String password = UUID.randomUUID().toString();

                    pure.registerUser(userId, password);
                }

                long finishTime = System.currentTimeMillis();
                System.out.println("That took: " + (finishTime - startTime) + " ms");
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
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, externalPublicKeys, storage);

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
                                                           String appToken,
                                                           String publicKey,
                                                           String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                            String appToken,
                                            String publicKey,
                                            String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
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
                                                  String appToken,
                                                  String publicKey,
                                                  String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
                Pure pure = new Pure(pureResult.getContext());

                String userId = UUID.randomUUID().toString();
                String password = UUID.randomUUID().toString();

                pure.registerUser(userId, password);

                UserRecord record = pure.getStorage().selectUser(userId);

                byte[] pwdHashDecrypted = pure.getCrypto().decrypt(record.getEncryptedPwdHash(), pureResult.getHkp().getPrivateKey());
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
                                           String appToken,
                                           String publicKey,
                                           String secretKey) throws InterruptedException {
        ThreadUtils.pause();

        try {
            PureSetupResult pureResult;
            StorageType[] storages = createStorages();
            for (StorageType storage: storages) {
                // TODO: Remove
                if (storage == StorageType.VirgilCloud) {
                    continue;
                }

                pureResult = this.setupPure(pheServerAddress, pureServerAddress, appToken, publicKey, secretKey, null, null, storage);
                Pure pure = new Pure(pureResult.getContext());

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
