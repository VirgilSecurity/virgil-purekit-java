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

package com.virgilsecurity.purekit;

import static com.virgilsecurity.crypto.phe.PheException.ERROR_AES_FAILED;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.*;
import java.util.stream.Stream;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.common.util.Base64;
import com.virgilsecurity.purekit.*;
import com.virgilsecurity.purekit.exception.PureException;
import com.virgilsecurity.purekit.storage.*;
import com.virgilsecurity.purekit.exception.PureCryptoException;
import com.virgilsecurity.purekit.exception.PureLogicException;
import com.virgilsecurity.purekit.model.*;
import com.virgilsecurity.purekit.storage.exception.PureStorageCellKeyNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageGenericException;
import com.virgilsecurity.purekit.storage.exception.PureStorageGrantKeyNotFoundException;
import com.virgilsecurity.purekit.storage.exception.PureStorageUserNotFoundException;
import com.virgilsecurity.purekit.storage.mariadb.MariaDbPureStorage;
import com.virgilsecurity.purekit.storage.mariadb.MariaDbSqlException;
import com.virgilsecurity.purekit.storage.ram.RamPureStorage;
import com.virgilsecurity.purekit.utils.PropertyManager;
import com.virgilsecurity.sdk.crypto.KeyPairType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PureTestJava {
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
                                      StorageType storageType) throws PureException {
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
                                      boolean skipClean) throws PureException {
        try {
            VirgilKeyPair bupkp = this.crypto.generateKeyPair(KeyPairType.ED25519);

            byte[] nmsData = nms;

            if (nmsData == null) {
                nmsData = this.crypto.generateRandomData(32);
            }
            String nmsString = String.format("NM.%s", Base64.encode(nmsData));

            String bupkpString = String.format("BU.%s", Base64.encode(this.crypto.exportPublicKey(bupkp.getPublicKey())));

            PureContext context;

            switch (storageType) {
                case RAM:
                    context = PureContext.createContext(appToken, nmsString, bupkpString,
                            secretKey, publicKey, new RamPureStorage(), externalPublicKeys,
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
                            secretKey, publicKey, mariaDbPureStorage, externalPublicKeys,
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
        catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
        catch (SQLException e) {
            throw new MariaDbSqlException(e);
        }
    }

    private static StorageType[] createStorages() {
        StorageType[] storages = new StorageType[3];

        storages[0] = StorageType.RAM;
        storages[1] = StorageType.VirgilCloud;
        storages[2] = StorageType.MariaDB;

        return storages;
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void registration__new_user__should_succeed(String pheServerAddress,
                                                String pureServerAddress,
                                                String kmsServerAddress,
                                                String appToken,
                                                String publicKey,
                                                String secretKey) throws PureException {
        PureSetupResult pureResult;

        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {
            pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
            Pure pure = new Pure(pureResult.getContext());

            String userId = UUID.randomUUID().toString();
            String password = UUID.randomUUID().toString();

            pure.registerUser(userId, password);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void authentication__new_user__should_succeed(String pheServerAddress,
                                                String pureServerAddress,
                                                String kmsServerAddress,
                                                String appToken,
                                                String publicKey,
                                                String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__random_data__should_match(String pheServerAddress,
                                               String pureServerAddress,
                                               String kmsServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void sharing__2_users__should_decrypt(String pheServerAddress,
                                          String pureServerAddress,
                                          String kmsServerAddress,
                                          String appToken,
                                          String publicKey,
                                          String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void sharing__revoke_access__should_not_decrypt(String pheServerAddress,
                                                    String pureServerAddress,
                                                    String kmsServerAddress,
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__change_password__should_not_decrypt(String pheServerAddress,
                                                    String pureServerAddress,
                                                    String kmsServerAddress,
                                                    String appToken,
                                                    String publicKey,
                                                    String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__expire__should_not_decrypt(String pheServerAddress,
                                           String pureServerAddress,
                                           String kmsServerAddress,
                                           String appToken,
                                           String publicKey,
                                           String secretKey) throws PureException, InterruptedException {
        PureSetupResult pureResult;
        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {
            pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
            Pure pure = new Pure(pureResult.getContext());

            String userId = UUID.randomUUID().toString();
            String password = UUID.randomUUID().toString();

            pure.registerUser(userId, password);

            AuthResult authResult = pure.authenticateUser(userId, password, new PureSessionParams(20));

            PureGrant grant1 = pure.decryptGrantFromUser(authResult.getEncryptedGrant());

            assertNotNull(grant1);

            Thread.sleep(16000);

            PureGrant grant2 = pure.decryptGrantFromUser(authResult.getEncryptedGrant());

            assertNotNull(grant2);

            Thread.sleep(8000);

            PureException ex = assertThrows(PureException.class, () -> {
                pure.decryptGrantFromUser(authResult.getEncryptedGrant());
            });

            if (ex instanceof PureLogicException) {
                assertEquals(PureLogicException.ErrorStatus.GRANT_IS_EXPIRED, ((PureLogicException)(ex)).getErrorStatus());
            }
            else if (ex instanceof PureStorageGrantKeyNotFoundException) { }
            else {
                assertEquals(0, 1);
            }
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__invalidate__should_not_decrypt(String pheServerAddress,
                                               String pureServerAddress,
                                               String kmsServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws PureException {
        PureSetupResult pureResult;
        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {
            pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
            Pure pure = new Pure(pureResult.getContext());

            String userId = UUID.randomUUID().toString();
            String password = UUID.randomUUID().toString();

            AuthResult authResult = pure.registerUser(userId, password, new PureSessionParams());

            pure.invalidateEncryptedUserGrant(authResult.getEncryptedGrant());

            PureStorageGrantKeyNotFoundException ex = assertThrows(PureStorageGrantKeyNotFoundException.class, () -> {
                pure.decryptGrantFromUser(authResult.getEncryptedGrant());
            });

            assertEquals(userId, ex.getUserId());
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void grant__admin_access__should_decrypt(String pheServerAddress,
                                             String pureServerAddress,
                                             String kmsServerAddress,
                                             String appToken,
                                             String publicKey,
                                             String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void reset_pwd__new_user__should_not_decrypt(String pheServerAddress,
                                                 String pureServerAddress,
                                                 String kmsServerAddress,
                                                 String appToken,
                                                 String publicKey,
                                                 String secretKey) throws PureException {
        PureSetupResult pureResult;
        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {
            pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
            Pure pure = new Pure(pureResult.getContext());

            String userId1 = UUID.randomUUID().toString();
            String password1 = UUID.randomUUID().toString();
            String userId2 = UUID.randomUUID().toString();
            String password21 = UUID.randomUUID().toString();
            String password22 = UUID.randomUUID().toString();
            String dataId1 = UUID.randomUUID().toString();
            String dataId2 = UUID.randomUUID().toString();
            byte[] text = UUID.randomUUID().toString().getBytes();

            AuthResult authResult1 = pure.registerUser(userId1, password1, new PureSessionParams());
            pure.registerUser(userId2, password21);

            byte[] cipherText1 = pure.encrypt(userId1, dataId1, text);
            pure.share(authResult1.getGrant(), dataId1, userId2);

            byte[] cipherText2 = pure.encrypt(userId2, dataId2, text);

            pure.resetUserPassword(userId2, password22, true);

            AuthResult authResult = pure.authenticateUser(userId2, password22);

            assertNotNull(authResult);

            PureLogicException e1 = assertThrows(PureLogicException.class, () -> {
                pure.decrypt(authResult.getGrant(), userId1, dataId1, cipherText1);
            });

            assertEquals(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA, e1.getErrorStatus());

            assertThrows(PureStorageCellKeyNotFoundException.class, () -> {
                pure.decrypt(authResult.getGrant(), null, dataId2, cipherText2);
            });
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void restore_pwd__new_user__should_decrypt(String pheServerAddress,
                                               String pureServerAddress,
                                               String kmsServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArguments")
    void rotation__local_storage__decrypt_and_recover_works(String pheServerAddress,
                                                            String pureServerAddress,
                                                            String kmsServerAddress,
                                                            String appToken,
                                                            String publicKeyOld,
                                                            String secretKeyOld,
                                                            String updateToken,
                                                            String publicKeyNew,
                                                            String secretKeyNew) throws PureException {
        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {
            // VirgilCloudPureStorage should not support that
            if (storage == StorageType.VirgilCloud) {
                continue;
            }

            long total = 20;

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

                Pure.RotationResults results = pure.performRotation();

                assertEquals(total, results.getUsersRotated());
                assertEquals(0, results.getGrantKeysRotated());
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
    }

    @ParameterizedTest @MethodSource("testArguments")
    void rotation__local_storage__grant_works(String pheServerAddress,
                                              String pureServerAddress,
                                              String kmsServerAddress,
                                              String appToken,
                                              String publicKeyOld,
                                              String secretKeyOld,
                                              String updateToken,
                                              String publicKeyNew,
                                              String secretKeyNew) throws PureException {
        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {
            // VirgilCloudPureStorage should not support that
            if (storage == StorageType.VirgilCloud) {
                continue;
            }

            long total = 20;

            PureStorage pureStorage;

            String firstUserId = null;
            String firstUserPwd = null;
            String dataId = UUID.randomUUID().toString();
            byte[] text = UUID.randomUUID().toString().getBytes();

            byte[] blob;
            byte[] nms;

            String encryptedGrant1;
            String encryptedGrant2;

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

                encryptedGrant1 = pure.authenticateUser(firstUserId, firstUserPwd).getEncryptedGrant();
            }

            {
                PureSetupResult pureResult = this.setupPure(nms, pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKeyOld, secretKeyOld, updateToken, null, storage, true);
                pureResult.getContext().setStorage(pureStorage);
                Pure pure = new Pure(pureResult.getContext());

                blob = pure.encrypt(firstUserId, dataId, text);

                encryptedGrant2 = pure.authenticateUser(firstUserId, firstUserPwd).getEncryptedGrant();

                Pure.RotationResults results = pure.performRotation();

                assertEquals(total, results.getUsersRotated());
                assertEquals(1, results.getGrantKeysRotated());
            }

            {
                PureSetupResult pureResult = this.setupPure(nms, pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKeyNew, secretKeyNew, null, null, storage, true);
                pureResult.getContext().setStorage(pureStorage);
                Pure pure = new Pure(pureResult.getContext());

                PureGrant pureGrant1 = pure.decryptGrantFromUser(encryptedGrant1);
                assertNotNull(pureGrant1);

                PureGrant pureGrant2 = pure.decryptGrantFromUser(encryptedGrant2);
                assertNotNull(pureGrant2);

                byte[] decrypted1 = pure.decrypt(pureGrant1, firstUserId, dataId, blob);
                assertArrayEquals(text, decrypted1);

                byte[] decrypted2 = pure.decrypt(pureGrant2, firstUserId, dataId, blob);
                assertArrayEquals(text, decrypted2);
            }

            {
                PureSetupResult pureResult = this.setupPure(nms, pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKeyOld, secretKeyOld, updateToken, null, storage, true);
                pureResult.getContext().setStorage(pureStorage);
                Pure pure = new Pure(pureResult.getContext());

                PureGrant pureGrant1 = pure.decryptGrantFromUser(encryptedGrant1);
                assertNotNull(pureGrant1);

                PureGrant pureGrant2 = pure.decryptGrantFromUser(encryptedGrant2);
                assertNotNull(pureGrant2);

                byte[] decrypted1 = pure.decrypt(pureGrant1, firstUserId, dataId, blob);
                assertArrayEquals(text, decrypted1);

                byte[] decrypted2 = pure.decrypt(pureGrant2, firstUserId, dataId, blob);
                assertArrayEquals(text, decrypted2);
            }
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__additional_keys__should_decrypt(String pheServerAddress,
                                                     String pureServerAddress,
                                                     String kmsServerAddress,
                                                     String appToken,
                                                     String publicKey,
                                                     String secretKey) throws PureException, CryptoException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__external_keys__should_decrypt(String pheServerAddress,
                                                   String pureServerAddress,
                                                   String kmsServerAddress,
                                                   String appToken,
                                                   String publicKey,
                                                   String secretKey) throws CryptoException, PureException {
        PureSetupResult pureResult;
        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {
            VirgilKeyPair keyPair = this.crypto.generateKeyPair();
            String dataId = UUID.randomUUID().toString();
            String publicKeyBase64 = Base64.encode(crypto.exportPublicKey(keyPair.getPublicKey()));
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_user__cascade__should_delete_user_and_keys(String pheServerAddress,
                                                           String pureServerAddress,
                                                           String kmsServerAddress,
                                                           String appToken,
                                                           String publicKey,
                                                           String secretKey) throws PureException {
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

            PureStorageUserNotFoundException e1 = assertThrows(PureStorageUserNotFoundException.class, () -> {
                pure.authenticateUser(userId, password);
            });

            assertTrue(e1.getUserIds().contains(userId));

            assertThrows(PureStorageCellKeyNotFoundException.class, () -> {
                pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);
            });
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_user__no_cascade__should_delete_user(String pheServerAddress,
                                                     String pureServerAddress,
                                                     String kmsServerAddress,
                                                     String appToken,
                                                     String publicKey,
                                                     String secretKey) throws PureException {
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

            PureStorageUserNotFoundException e = assertThrows(PureStorageUserNotFoundException.class, () -> {
                pure.authenticateUser(userId, password);
            });

            assertTrue(e.getUserIds().contains(userId));

            byte[] plainText = pure.decrypt(authResult1.getGrant(), null, dataId, cipherText);

            assertArrayEquals(text, plainText);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_key__new_key__should_delete(String pheServerAddress,
                                            String pureServerAddress,
                                            String kmsServerAddress,
                                            String appToken,
                                            String publicKey,
                                            String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void registration__new_user__backups_pwd_hash(String pheServerAddress,
                                                  String pureServerAddress,
                                                  String kmsServerAddress,
                                                  String appToken,
                                                  String publicKey,
                                                  String secretKey) throws PureException, DecryptionException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void encryption__roles__should_decrypt(String pheServerAddress,
                                           String pureServerAddress,
                                           String kmsServerAddress,
                                           String appToken,
                                           String publicKey,
                                           String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void delete_roles__new_role__should_delete(String pheServerAddress,
                                               String pureServerAddress,
                                               String kmsServerAddress,
                                               String appToken,
                                               String publicKey,
                                               String secretKey) throws PureException {
        PureSetupResult pureResult;
        StorageType[] storages = createStorages();
        for (StorageType storage: storages) {

            if (storage == StorageType.VirgilCloud) {
                // FIXME: Remove
                continue;
            }

            pureResult = this.setupPure(pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, storage);
            Pure pure = new Pure(pureResult.getContext());

            String userId1 = UUID.randomUUID().toString();
            String userId2 = UUID.randomUUID().toString();
            String password1 = UUID.randomUUID().toString();
            String password2 = UUID.randomUUID().toString();
            String dataId1 = UUID.randomUUID().toString();
            String dataId2 = UUID.randomUUID().toString();
            String roleName1 = UUID.randomUUID().toString();
            String roleName2 = UUID.randomUUID().toString();

            pure.registerUser(userId1, password1);
            pure.registerUser(userId2, password2);

            byte[] text1 = UUID.randomUUID().toString().getBytes();
            byte[] text2 = UUID.randomUUID().toString().getBytes();

            AuthResult authResult1 = pure.authenticateUser(userId1, password1);
            AuthResult authResult2 = pure.authenticateUser(userId2, password2);

            pure.createRole(roleName1, Collections.singleton(userId1));
            pure.createRole(roleName2, Collections.singleton(userId2));

            byte[] cipherText1 = pure.encrypt(userId1, dataId1, Collections.emptySet(), Collections.singleton(roleName2), Collections.emptyList(), text1);
            byte[] cipherText2 = pure.encrypt(userId2, dataId2, Collections.emptySet(), Collections.singleton(roleName1), Collections.emptyList(), text2);

            pure.deleteRole(roleName1, true);
            PureLogicException e = assertThrows(PureLogicException.class, () -> {
                pure.decrypt(authResult1.getGrant(), userId2, dataId2, cipherText2);
            });
            assertEquals(PureLogicException.ErrorStatus.USER_HAS_NO_ACCESS_TO_DATA, e.getErrorStatus());

            if (storage != StorageType.MariaDB) {
                pure.deleteRole(roleName2, false);
                byte[] plainText = pure.decrypt(authResult2.getGrant(), userId1, dataId1, cipherText1);
                assertArrayEquals(text1, plainText);
            }
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void recovery__new_user__should_recover(String pheServerAddress,
                                            String pureServerAddress,
                                            String kmsServerAddress,
                                            String appToken,
                                            String publicKey,
                                            String secretKey) throws PureException {
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
    }

    @ParameterizedTest @MethodSource("testArgumentsNoToken")
    void share__role__should_decrypt(String pheServerAddress,
                                     String pureServerAddress,
                                     String kmsServerAddress,
                                     String appToken,
                                     String publicKey,
                                     String secretKey) throws PureException {
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
            String roleName = UUID.randomUUID().toString();

            AuthResult authResult1 = pure.registerUser(userId1, password1, new PureSessionParams());
            AuthResult authResult2 = pure.registerUser(userId2, password2, new PureSessionParams());

            byte[] text = UUID.randomUUID().toString().getBytes();

            byte[] blob = pure.encrypt(userId1, dataId, text);

            pure.createRole(roleName, Collections.singleton(userId2));

            pure.shareToRole(authResult1.getGrant(), dataId, roleName);

            byte[] decrypted = pure.decrypt(authResult2.getGrant(), userId1, dataId, blob);
            assertArrayEquals(text, decrypted);
        }
    }

    @ParameterizedTest @MethodSource("testArgumentsComp")
    void cross_compatibility__json__should_work(String pheServerAddress,
                                                String pureServerAddress,
                                                String kmsServerAddress,
                                                String appToken,
                                                String publicKey,
                                                String secretKey,
                                                String env) throws PureException, SQLException, IOException {
        JsonObject testData = (JsonObject) new JsonParser()
                .parse(new InputStreamReader(Objects.requireNonNull(
                        this.getClass().getClassLoader()
                                .getResourceAsStream(
                                        "com/virgilsecurity/purekit/compatibility_data_" + env + ".json"))));

        String encryptedGrant = testData.get("encrypted_grant").getAsString();
        String userId1 = testData.get("user_id1").getAsString();
        String userId2 = testData.get("user_id2").getAsString();
        String password1 = testData.get("password1").getAsString();
        String password2 = testData.get("password2").getAsString();
        String dataId1 = testData.get("data_id1").getAsString();
        String dataId2 = testData.get("data_id2").getAsString();
        byte[] text1 = Base64.decode(testData.get("text1").getAsString());
        byte[] text2 = Base64.decode(testData.get("text2").getAsString());
        byte[] blob1 = Base64.decode(testData.get("blob1").getAsString());
        byte[] blob2 = Base64.decode(testData.get("blob2").getAsString());
        byte[] nms = Base64.decode(testData.get("nms").getAsString());

        PureSetupResult pureResult = this.setupPure(nms, pheServerAddress, pureServerAddress, kmsServerAddress, appToken, publicKey, secretKey, null, null, StorageType.MariaDB, true);
        Pure pure = new Pure(pureResult.getContext());

        MariaDbPureStorage mariaDbPureStorage = (MariaDbPureStorage) pureResult.getContext().getStorage();

        List<String> sqls = Files.readAllLines(Paths.get(this.getClass().getClassLoader().getResource("com/virgilsecurity/purekit/compatibility_tables_" + env + ".sql").getPath()), StandardCharsets.UTF_8);

        mariaDbPureStorage.cleanDb();

        for (String sql: sqls) {
            mariaDbPureStorage.executeSql(sql);
        }

        PureGrant pureGrant = pure.decryptGrantFromUser(encryptedGrant);

        assertNotNull(pureGrant);

        AuthResult authResult1 = pure.authenticateUser(userId1, password1);
        AuthResult authResult2 = pure.authenticateUser(userId2, password2);

        assertNotNull(authResult1);
        assertNotNull(authResult2);

        byte[] text11 = pure.decrypt(authResult1.getGrant(), null, dataId1, blob1);
        byte[] text12 = pure.decrypt(authResult2.getGrant(), userId1, dataId1, blob1);
        byte[] text21 = pure.decrypt(authResult1.getGrant(), null, dataId2, blob2);
        byte[] text22 = pure.decrypt(authResult2.getGrant(), userId1, dataId2, blob2);

        assertArrayEquals(text1, text11);
        assertArrayEquals(text1, text12);
        assertArrayEquals(text2, text21);
        assertArrayEquals(text2, text22);
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

    private static Stream<Arguments> testArgumentsComp() {
        return Stream.of(
                Arguments.of(PropertyManager.getPheServiceAddress(),
                        PropertyManager.getPureServerAddress(),
                        PropertyManager.getKmsServerAddress(),
                        PropertyManager.getAppToken(),
                        PropertyManager.getPublicKeyNew(),
                        PropertyManager.getSecretKeyNew(),
                        PropertyManager.getEnv())
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
