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

package com.virgilsecurity.purekit.pure;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.virgilsecurity.crypto.foundation.Base64;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.utils.ValidateUtils;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * PureContext class represents dependencies needed to initialize Pure.
 */
public class PureContext {

    static class Credentials {
        private byte[] payload;
        private int version;

        private Credentials(byte[] payload, int version) {
            this.payload = payload;
            this.version = version;
        }

        byte[] getPayload() {
            return payload;
        }

        int getVersion() {
            return version;
        }
    }

    private static final String NMS_PREFIX = "NM";
    private static final String BUPPK_PREFIX = "BU";
    private static final String SECRET_KEY_PREFIX = "SK";
    private static final String PUBLIC_KEY_PREFIX = "PK";

    private final VirgilCrypto crypto;
    private final VirgilPublicKey buppk;
    private final Credentials appSecretKey;
    private final Credentials servicePublicKey;
    private final NonrotatableSecrets nonrotatableSecrets;
    private PureStorage storage;
    private final HttpPheClient pheClient;
    private final Map<String, List<VirgilPublicKey>> externalPublicKeys;
    private Credentials updateToken;

    private PureContext(VirgilCrypto crypto,
                        String appToken,
                        String nms,
                        String buppk,
                        String appSecretKey,
                        String servicePublicKey,
                        PureStorage storage,
                        Map<String, List<String>> externalPublicKeys,
                        String pheServiceAddress) throws PureLogicException, CryptoException {
        ValidateUtils.checkNull(storage, "storage");

        this.crypto = crypto;

        Credentials nmsCred = PureContext.parseCredentials(NMS_PREFIX, nms, false);
        this.nonrotatableSecrets = NonrotatableSecretsGenerator.generateSecrets(nmsCred.getPayload());

        byte[] buppkData = PureContext.parseCredentials(BUPPK_PREFIX, buppk, false).getPayload();
        this.buppk = crypto.importPublicKey(buppkData);

        this.appSecretKey = PureContext.parseCredentials(SECRET_KEY_PREFIX, appSecretKey, true);
        this.servicePublicKey = PureContext.parseCredentials(PUBLIC_KEY_PREFIX, servicePublicKey, true);
        this.pheClient = new HttpPheClient(appToken, pheServiceAddress);

        if (storage instanceof PureModelSerializerDependent) {
            PureModelSerializerDependent dependent = (PureModelSerializerDependent)storage;

            PureModelSerializer serializer = new PureModelSerializer(crypto, this.nonrotatableSecrets.getVskp());
            dependent.setPureModelSerializer(serializer);
        }

        this.storage = storage;

        if (externalPublicKeys != null) {
            this.externalPublicKeys = new HashMap<>(externalPublicKeys.size());
            for (String key : externalPublicKeys.keySet()) {
                List<String> publicKeysBase64 = externalPublicKeys.get(key);
                ArrayList<VirgilPublicKey> publicKeys = new ArrayList<>(publicKeysBase64.size());

                for (String publicKeyBase64 : publicKeysBase64) {
                    VirgilPublicKey publicKey =
                        crypto.importPublicKey(Base64.decode(publicKeyBase64.getBytes()));
                    publicKeys.add(publicKey);
                }

                this.externalPublicKeys.put(key, publicKeys);
            }
        } else {
            this.externalPublicKeys = new HashMap<>();
        }

        if (this.appSecretKey.getVersion() != this.servicePublicKey.getVersion()) {
            throw new PureLogicException(PureLogicException.ErrorStatus.KEYS_VERSION_MISMATCH);
        }
    }

    /**
     * Designed for usage with Virgil Cloud storage.
     *
     * @param appToken Application token.
     * @param nms Nonrotatable master secret.
     * @param bu Backup public key.
     * @param sk App secret key.
     * @param pk Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     */
    public static PureContext createContext(String appToken,
                                            String nms,
                                            String bu,
                                            String sk,
                                            String pk,
                                            Map<String, List<String>> externalPublicKeys)
        throws CryptoException, PureLogicException {

        return PureContext.createContext(
            appToken,
            nms, bu, sk, pk,
            externalPublicKeys,
            HttpPheClient.SERVICE_ADDRESS,
            HttpPureClient.SERVICE_ADDRESS
        );
    }

    /**
     * Designed for usage with Virgil Cloud storage.
     *
     * @param appToken Application token.
     * @param nms Nonrotatable master secret.
     * @param bu Backup public key.
     * @param sk App secret key.
     * @param pk Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     * @param pheServiceAddress PHE service address.
     * @param pureServiceAddress Pure service address.
     */
    public static PureContext createContext(String appToken,
                                            String nms,
                                            String bu,
                                            String sk,
                                            String pk,
                                            Map<String, List<String>> externalPublicKeys,
                                            String pheServiceAddress,
                                            String pureServiceAddress)
        throws CryptoException, PureLogicException {

        VirgilCrypto crypto = new VirgilCrypto();
        HttpPureClient pureClient = new HttpPureClient(appToken, pureServiceAddress);

        PureStorage storage = new VirgilCloudPureStorage(crypto, pureClient);

        return new PureContext(
            crypto,
            appToken,
            nms, bu, sk, pk,
            storage,
            externalPublicKeys,
            pheServiceAddress
        );
    }

    /**
     * Designed for usage with custom PureStorage.
     *
     * @param appToken Application token.
     * @param nms Nonrotatable master secret.
     * @param bu Backup public key.
     * @param storage PureStorage.
     * @param appSecretKey App secret key.
     * @param servicePublicKey Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     */
    public static PureContext createContext(String appToken,
                                            String nms,
                                            String bu,
                                            PureStorage storage,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys)
        throws CryptoException, PureLogicException {

        return PureContext.createContext(
            appToken,
            nms, bu,
            storage,
            appSecretKey,
            servicePublicKey,
            externalPublicKeys,
            HttpPheClient.SERVICE_ADDRESS
        );
    }

    /**
     * Designed for usage with custom PureStorage.
     *
     * @param appToken Application token.
     * @param nms Nonrotatable master secret.
     * @param bu Backup public key.
     * @param storage PureStorage.
     * @param appSecretKey App secret key.
     * @param servicePublicKey Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     * @param pheServiceAddress PHE service address.
     */
    public static PureContext createContext(String appToken,
                                            String nms,
                                            String bu,
                                            PureStorage storage,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys,
                                            String pheServiceAddress)
        throws CryptoException, PureLogicException {

        return new PureContext(
            new VirgilCrypto(),
            appToken, nms, bu,
            appSecretKey,
            servicePublicKey,
            storage,
            externalPublicKeys,
            pheServiceAddress
        );
    }

    private static Credentials parseCredentials(String prefix,
                                                String credentials,
                                                boolean isVersioned) throws PureLogicException {
        ValidateUtils.checkNullOrEmpty(prefix, "prefix");
        ValidateUtils.checkNullOrEmpty(credentials, "credentials");

        String[] parts = credentials.split("\\.");

        if (parts.length != (isVersioned ? 3 : 2)) {
            throw new PureLogicException(PureLogicException.ErrorStatus.CREDENTIALS_PARSING_ERROR);
        }

        int index = 0;

        if (!parts[index].equals(prefix)) {
            throw new PureLogicException(PureLogicException.ErrorStatus.CREDENTIALS_PARSING_ERROR);
        }
        index++;

        int version;
        if (isVersioned) {
            version = Integer.parseInt(parts[index]);
            index++;
        } else {
            version = 0;
        }

        byte[] payload = Base64.decode(parts[index].getBytes());

        return new Credentials(payload, version);
    }

    /**
     * Returns PureStorage.
     *
     * @return PureStorage.
     */
    public PureStorage getStorage() {
        return storage;
    }

    /**
     * Returns PureStorage.
     *
     * @return PureStorage.
     */
    public Credentials getUpdateToken() {
        return updateToken;
    }

    /**
     * Sets Update token.
     */
    public void setUpdateToken(String updateToken) throws PureLogicException {
        this.updateToken = PureContext.parseCredentials("UT", updateToken, true);

        if (this.updateToken.getVersion() != this.appSecretKey.getVersion() + 1) {
            throw new PureLogicException(PureLogicException.ErrorStatus.UPDATE_TOKEN_VERSION_MISMATCH);
        }
    }

    public void setStorage(PureStorage storage) {
        this.storage = storage;
    }

    /**
     * Returns backup public key.
     *
     * @return Backup public key.
     */
    public VirgilPublicKey getBuppk() {
        return buppk;
    }

    /**
     * Returns app secret key.
     *
     * @return App secret key.
     */
    public Credentials getAppSecretKey() {
        return appSecretKey;
    }

    /**
     * Returns service public key.
     *
     * @return Service public key.
     */
    public Credentials getServicePublicKey() {
        return servicePublicKey;
    }

    /**
     * Returns phe client.
     *
     * @return PHE client.
     */
    public HttpPheClient getPheClient() {
        return pheClient;
    }

    /**
     * Returns external public keys.
     *
     * @return external public keys.
     */
    public Map<String, List<VirgilPublicKey>> getExternalPublicKeys() {
        return externalPublicKeys;
    }

    /**
     * Returns crypto.
     *
     * @return VirgilCrypto.
     */
    public VirgilCrypto getCrypto() {
        return crypto;
    }

    public NonrotatableSecrets getNonrotatableSecrets() {
        return nonrotatableSecrets;
    }
}
