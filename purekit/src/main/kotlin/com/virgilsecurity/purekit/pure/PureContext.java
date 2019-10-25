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
import com.virgilsecurity.purekit.pure.exception.PureException;
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

    private static final int AK_LENGTH = 32;
    private static final String AK_PREFIX = "AK";
    private static final String BUPPK_PREFIX = "BU";
    private static final String HPK_PREFIX = "HB";
    private static final String SECRET_KEY_PREFIX = "SK";
    private static final String PUBLIC_KEY_PREFIX = "PK";
    private static final String VIRGIL_SIGNING_KEY_PREFIX = "VS";
    private static final String OWN_SIGNING_KEY_PREFIX = "OS";

    private final VirgilCrypto crypto;
    private final Credentials ak;
    private final VirgilPublicKey buppk;
    private final VirgilPublicKey hpk;
    private final VirgilKeyPair oskp;
    private final Credentials appSecretKey;
    private final Credentials servicePublicKey;
    private final PureStorage storage;
    private final HttpPheClient pheClient;
    private final Map<String, List<VirgilPublicKey>> externalPublicKeys;
    private Credentials updateToken;

    private PureContext(VirgilCrypto crypto,
                        String appToken,
                        String ak,
                        String buppk,
                        String hpk,
                        String oskp,
                        String appSecretKey,
                        String servicePublicKey,
                        PureStorage storage,
                        Map<String, List<String>> externalPublicKeys,
                        String pheServiceAddress) throws PureException, CryptoException {
        ValidateUtils.checkNull(storage, "storage");

        this.crypto = crypto;
        this.ak = PureContext.parseCredentials(AK_PREFIX, ak, false);

        byte[] buppkData = PureContext.parseCredentials(BUPPK_PREFIX, buppk, false).getPayload();
        this.buppk = crypto.importPublicKey(buppkData);

        byte[] hpkData = PureContext.parseCredentials(HPK_PREFIX, hpk, false).getPayload();
        this.hpk = crypto.importPublicKey(hpkData);

        byte[] osskData = PureContext.parseCredentials(OWN_SIGNING_KEY_PREFIX, oskp, false).getPayload();
        this.oskp = crypto.importPrivateKey(osskData);

        this.appSecretKey = PureContext.parseCredentials(SECRET_KEY_PREFIX, appSecretKey, true);
        this.servicePublicKey = PureContext.parseCredentials(PUBLIC_KEY_PREFIX,
                                                             servicePublicKey,
                                                             true);
        this.storage = storage;
        this.pheClient = new HttpPheClient(appToken, pheServiceAddress);

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
            throw new PureException(PureException.ErrorStatus.KEYS_VERSION_MISMATCH);
        }

        if (this.ak.getPayload().length != AK_LENGTH) {
            throw new PureException(PureException.ErrorStatus.AK_INVALID_LENGTH);
        }
    }

    /**
     * Designed for usage with Virgil Cloud storage.
     *
     * @param appToken Application token.
     * @param ak Authentication symmetric key.
     * @param bu Backup public key.
     * @param hb Password hashes backup public key.
     * @param os Private key used to sign data during encryption.
     * @param vs Private key used to sign records before sending to Virgil cloud.
     * @param sk App secret key.
     * @param pk Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     */
    public static PureContext createContext(String appToken,
                                            String ak,
                                            String bu,
                                            String hb,
                                            String os,
                                            String vs,
                                            String sk,
                                            String pk,
                                            Map<String, List<String>> externalPublicKeys)
        throws CryptoException, PureException {

        return PureContext.createContext(appToken, ak, bu, hb, os, vs, sk, pk,
                                         externalPublicKeys, HttpPheClient.SERVICE_ADDRESS,
                                         HttpPureClient.SERVICE_ADDRESS);
    }

    /**
     * Designed for usage with Virgil Cloud storage.
     *
     * @param appToken Application token.
     * @param ak Authentication symmetric key.
     * @param bu Backup public key.
     * @param hb Password hashes backup public key.
     * @param os Private key used to sign data during encryption.
     * @param vs Private key used to sign records before sending to Virgil cloud,
     *              if null, setStorage should be called.
     * @param sk App secret key.
     * @param pk Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     * @param pheServiceAddress PHE service address.
     * @param pureServiceAddress Pure service address.
     */
    public static PureContext createContext(String appToken,
                                            String ak,
                                            String bu,
                                            String hb,
                                            String os,
                                            String vs,
                                            String sk,
                                            String pk,
                                            Map<String, List<String>> externalPublicKeys,
                                            String pheServiceAddress,
                                            String pureServiceAddress)
        throws CryptoException, PureException {

        VirgilCrypto crypto = new VirgilCrypto();
        HttpPureClient pureClient = new HttpPureClient(appToken, pureServiceAddress);
        Credentials vkCredentials =
            PureContext.parseCredentials(VIRGIL_SIGNING_KEY_PREFIX, vs, false);
        PureStorage storage = new VirgilCloudPureStorage(
            crypto,
            pureClient,
            crypto.importPrivateKey(vkCredentials.getPayload())
        );

        return new PureContext(crypto, appToken, ak, bu, hb, os, sk, pk, storage, externalPublicKeys, pheServiceAddress);
    }

    /**
     * Designed for usage with custom PureStorage.
     *
     * @param appToken Application token.
     * @param ak Authentication symmetric key.
     * @param bu Backup public key.
     * @param hb Password hashes backup public key.
    *  @param os Private key used to sign data during encryption.
     * @param storage PureStorage.
     * @param appSecretKey App secret key.
     * @param servicePublicKey Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     */
    public static PureContext createContext(String appToken,
                                            String ak,
                                            String bu,
                                            String hb,
                                            String os,
                                            PureStorage storage,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys)
        throws CryptoException, PureException {

        return PureContext.createContext(appToken, ak, bu, hb, os, storage,
                                         appSecretKey, servicePublicKey, externalPublicKeys,
                                         HttpPheClient.SERVICE_ADDRESS);
    }

    /**
     * Designed for usage with custom PureStorage.
     *
     * @param appToken Application token.
     * @param ak Authentication symmetric key.
     * @param bu Backup public key.
     * @param hb Password hashes backup public key.
     * @param os Private key used to sign data during encryption.
     * @param storage PureStorage.
     * @param appSecretKey App secret key.
     * @param servicePublicKey Service public key.
     * @param externalPublicKeys External public keys that will be added during encryption by
     *                           default. Map key is dataId, value is list of base64 public keys.
     * @param pheServiceAddress PHE service address.
     */
    public static PureContext createContext(String appToken,
                                            String ak,
                                            String bu,
                                            String hb,
                                            String os,
                                            PureStorage storage,
                                            String appSecretKey,
                                            String servicePublicKey,
                                            Map<String, List<String>> externalPublicKeys,
                                            String pheServiceAddress)
        throws CryptoException, PureException {

        return new PureContext(new VirgilCrypto(), appToken, ak, bu, hb, os,
                               appSecretKey, servicePublicKey, storage, externalPublicKeys,
                               pheServiceAddress);
    }

    private static Credentials parseCredentials(String prefix,
                                                String credentials,
                                                boolean isVersioned) throws PureException {
        ValidateUtils.checkNullOrEmpty(prefix, "prefix");
        ValidateUtils.checkNullOrEmpty(credentials, "credentials");

        String[] parts = credentials.split("\\.");

        if (parts.length != (isVersioned ? 3 : 2)) {
            throw new PureException(PureException.ErrorStatus.CREDENTIALS_PARSING_ERROR);
        }

        int index = 0;

        if (!parts[index].equals(prefix)) {
            throw new PureException(PureException.ErrorStatus.CREDENTIALS_PARSING_ERROR);
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
    public void setUpdateToken(String updateToken) throws PureException {
        this.updateToken = PureContext.parseCredentials("UT", updateToken, true);

        if (this.updateToken.getVersion() != this.appSecretKey.getVersion() + 1) {
            throw new PureException(PureException.ErrorStatus.UPDATE_TOKEN_VERSION_MISMATCH);
        }
    }

    /**
     * Returns authentication symmetric key.
     *
     * @return Authentication symmetric key.
     */
    public Credentials getAk() {
        return ak;
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
     * Returns OS key pair.
     *
     * @return OS key pair.
     */
    public VirgilKeyPair getOskp() {
        return oskp;
    }

    /**
     * Returns password hashes backup public key.
     *
     * @return Password hashes backup public key.
     */
    public VirgilPublicKey getHpk() {
        return hpk;
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
}
