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

import com.virgilsecurity.purekit.client.HttpClientProtobuf;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import java.util.*;

/**
 * Dependencies needed to initialize Pure
 */
public class PureContext {
    static class Credentials {
        private byte[] payload;
        private int version;

        byte[] getPayload() {
            return payload;
        }

        int getVersion() {
            return version;
        }

        private Credentials(byte[] payload, int version) {
            this.payload = payload;
            this.version = version;
        }
    }

    static private Credentials parseCredentials(String prefix, String credentials, boolean isVersioned) throws PureException {
        if (prefix == null || prefix.isEmpty()) {
            throw new NullPointerException();
        }
        if (credentials == null || credentials.isEmpty()) {
            throw new NullPointerException();
        }

        String[] parts = credentials.split("\\.");

        if (parts.length != (isVersioned ? 3 : 2)) {
            throw new PureException(PureException.ErrorCode.CREDENTIALS_PARSING_ERROR);
        }

        int index = 0;

        if (!parts[index].equals(prefix)) {
            throw new PureException(PureException.ErrorCode.CREDENTIALS_PARSING_ERROR);
        }
        index++;

        int version;
        if (isVersioned) {
            version = Integer.parseInt(parts[index]);
            index++;
        }
        else {
            version = 0;
        }

        byte[] payload = Base64.getDecoder().decode(parts[index]);

        return new Credentials(payload, version);
    }

    static final private int akLength = 32;

    private final VirgilCrypto crypto;
    private final Credentials ak;
    private final VirgilPublicKey buppk;
    private final VirgilPublicKey hpk;
    private final Credentials appSecretKey;
    private final Credentials servicePublicKey;
    private Credentials updateToken;
    private final PureStorage storage;
    private final HttpPheClient pheClient;
    private final Map<String, List<VirgilPublicKey>> externalPublicKeys;

    private PureContext(VirgilCrypto crypto,
                        String appToken,
                        String ak,
                        String buppk,
                        String hpk,
                        String appSecretKey,
                        String servicePublicKey,
                        PureStorage storage,
                        Map<String, List<String>> externalPublicKeys,
                        String pheServiceAddress) throws PureException, CryptoException {
        this.crypto = crypto;

        if (storage == null) {
            throw new NullPointerException();
        }

        this.ak = PureContext.parseCredentials("AK", ak, false);
        byte[] buppkData = PureContext.parseCredentials("BU", buppk, false).getPayload();
        this.buppk = this.crypto.importPublicKey(buppkData);

        byte[] hpkData = PureContext.parseCredentials("HB", hpk, false).getPayload();
        this.hpk = this.crypto.importPublicKey(hpkData);

        this.appSecretKey = PureContext.parseCredentials("SK", appSecretKey, true);
        this.servicePublicKey = PureContext.parseCredentials("PK", servicePublicKey, true);
        this.storage = storage;
        this.pheClient = new HttpPheClient(appToken, pheServiceAddress);

        if (externalPublicKeys != null) {
            // FIXME: I hate java
            this.externalPublicKeys = new HashMap<>(externalPublicKeys.size());
            for (String key : externalPublicKeys.keySet()) {
                List<String> publicKeysBase64 = externalPublicKeys.get(key);
                ArrayList<VirgilPublicKey> publicKeys = new ArrayList<>(publicKeysBase64.size());

                for (String publicKeyBase64 : publicKeysBase64) {
                    VirgilPublicKey publicKey = this.crypto.importPublicKey(Base64.getDecoder().decode(publicKeyBase64));
                    publicKeys.add(publicKey);
                }

                this.externalPublicKeys.put(key, publicKeys);
            }
        }
        else {
            this.externalPublicKeys = new HashMap<>();
        }

        if (this.appSecretKey.getVersion() != this.servicePublicKey.getVersion()) {
            throw new PureException(PureException.ErrorCode.KEYS_VERSION_MISMATCH);
        }

        if (this.ak.getPayload().length != PureContext.akLength) {
            throw new PureException(PureException.ErrorCode.AK_INVALID_LENGTH);
        }
    }

    /**
     * Fabric. Designed for usage with Virgil Cloud storage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param cloudSigningKeyBase64 Private key used to sign records before sending to Virgil cloud
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     */
    static public PureContext createContext(String appToken,
                                            String akBase64,
                                            String buppkBase64,
                                            String hpkBase64,
                                            String cloudSigningKeyBase64,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys) throws CryptoException, PureException {
        return PureContext.createContext(appToken, akBase64, buppkBase64, hpkBase64,
                cloudSigningKeyBase64, appSecretKey, servicePublicKey, externalPublicKeys,
                HttpPheClient.serviceAddress, HttpPureClient.serviceAddress);
    }

    /**
     * Fabric. Designed for usage with Virgil Cloud storage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param cloudSigningKeyBase64 Private key used to sign records before sending to Virgil cloud, if null, setStorage should be called
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     * @param pheServiceAddress PHE service address
     * @param pureServiceAddress Pure service address
     */
    static public PureContext createContext(String appToken,
                                            String akBase64,
                                            String buppkBase64,
                                            String hpkBase64,
                                            String cloudSigningKeyBase64,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys,
                                            String pheServiceAddress,
                                            String pureServiceAddress) throws CryptoException, PureException {
        VirgilCrypto crypto = new VirgilCrypto();
        HttpPureClient pureClient = new HttpPureClient(appToken, pureServiceAddress);
        Credentials vkCredentials = PureContext.parseCredentials("VK", cloudSigningKeyBase64, false);
        PureStorage storage = new VirgilCloudPureStorage(crypto, pureClient, crypto.importPrivateKey(vkCredentials.getPayload()));

        return new PureContext(crypto, appToken, akBase64, buppkBase64, hpkBase64, appSecretKey,
                servicePublicKey, storage, externalPublicKeys, pheServiceAddress);
    }

    /**
     * Fabric. Designed for usage with custom PureStorage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param storage PureStorage
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     */
    static public PureContext createContext(String appToken,
                                            String akBase64,
                                            String buppkBase64,
                                            String hpkBase64,
                                            PureStorage storage,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys) throws CryptoException, PureException {
        return PureContext.createContext(appToken, akBase64,buppkBase64, hpkBase64, storage, appSecretKey,
                servicePublicKey,  externalPublicKeys,
                HttpPheClient.serviceAddress);
    }

    /**
     * Fabric. Designed for usage with custom PureStorage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param storage PureStorage
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     * @param pheServiceAddress PHE service address
     */
    static public PureContext createContext(String appToken,
                                            String akBase64,
                                            String buppkBase64,
                                            String hpkBase64,
                                            PureStorage storage,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys,
                                            String pheServiceAddress) throws CryptoException, PureException {
        return new PureContext(new VirgilCrypto(), appToken, akBase64, buppkBase64, hpkBase64, appSecretKey, servicePublicKey,
                storage, externalPublicKeys, pheServiceAddress);
    }

    /**
     * Returns PureStorage
     * @return PureStorage
     */
    public PureStorage getStorage() {
        return storage;
    }
    /**
     * Returns PureStorage
     * @return PureStorage
     */
    public Credentials getUpdateToken() {
        return updateToken;
    }
    /**
     * Sets Update token
     */
    public void setUpdateToken(String updateToken) throws PureException {
        this.updateToken = PureContext.parseCredentials("UT", updateToken, true);

        if (this.updateToken.getVersion() != this.appSecretKey.getVersion() + 1) {
            throw new PureException(PureException.ErrorCode.UPDATE_TOKEN_VERSION_MISMATCH);
        }
    }
    /**
     * Returns authentication symmetric key
     * @return Authentication symmetric key
     */
    public Credentials getAk() {
        return ak;
    }
    /**
     * Returns backup public key
     * @return Backup public key
     */
    public VirgilPublicKey getBuppk() {
        return buppk;
    }
    /**
     * Returns password hashes backup public key
     * @return Password hashes backup public key
     */
    public VirgilPublicKey getHpk() {
        return hpk;
    }
    /**
     * Returns app secret key
     * @return App secret key
     */
    public Credentials getAppSecretKey() {
        return appSecretKey;
    }
    /**
     * Returns service public key
     * @return Service public key
     */
    public Credentials getServicePublicKey() {
        return servicePublicKey;
    }
    /**
     * Returns phe client
     * @return PHE client
     */
    public HttpPheClient getPheClient() {
        return pheClient;
    }
    /**
     * Returns external public keys
     * @return external public keys
     */
    public Map<String, List<VirgilPublicKey>> getExternalPublicKeys() {
        return externalPublicKeys;
    }
    /**
     * Returns crypto
     * @return VirgilCrypto
     */
    public VirgilCrypto getCrypto() {
        return crypto;
    }
}
