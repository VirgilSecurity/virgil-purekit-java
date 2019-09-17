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
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Dependencies needed to initialize Pure
 */
public class PureContext {
    private PureStorage storage;
    private byte[] ak;
    private byte[] buppk;
    private byte[] hpk;
    private String appSecretKey;
    private String servicePublicKey;
    private String updateToken;
    private HttpPureClient client;
    private Map<String, List<String>> externalPublicKeys;

    /**
     * Constructor. Designed for usage with Virgil Cloud storage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param cloudSigningKeyBase64 Private key used to sign records before sending to Virgil cloud, if null, setStorage should be called
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     */
    public PureContext(String appToken,
                       String akBase64,
                       String buppkBase64,
                       String hpkBase64,
                       String cloudSigningKeyBase64,
                       String appSecretKey,
                       String servicePublicKey,
                       Map<String, List<String>> externalPublicKeys) throws CryptoException {
        this(appToken, akBase64, buppkBase64, hpkBase64, cloudSigningKeyBase64, appSecretKey, servicePublicKey, externalPublicKeys, "https://api.virgilsecurity.com/phe/v1" /* FIXME */);
    }

    /**
     * Constructor. Designed for usage with Virgil Cloud storage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param cloudSigningKeyBase64 Private key used to sign records before sending to Virgil cloud, if null, setStorage should be called
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     * @param serviceAddress Service address
     */
    public PureContext(String appToken,
                       String akBase64,
                       String buppkBase64,
                       String hpkBase64,
                       String cloudSigningKeyBase64,
                       String appSecretKey,
                       String servicePublicKey,
                       Map<String, List<String>> externalPublicKeys,
                       String serviceAddress) throws CryptoException {
        if (appSecretKey == null || appSecretKey.isEmpty()) {
            throw new NullPointerException();
        }
        if (servicePublicKey == null || servicePublicKey.isEmpty()) {
            throw new NullPointerException();
        }

        this.externalPublicKeys = externalPublicKeys;
        this.ak = Base64.getDecoder().decode(akBase64);
        this.buppk = Base64.getDecoder().decode(buppkBase64);
        this.hpk = Base64.getDecoder().decode(hpkBase64);
        this.appSecretKey = appSecretKey;
        this.servicePublicKey = servicePublicKey;
        this.client = new HttpPureClient(appToken, serviceAddress);
        this.storage = new VirgilCloudPureStorage(this.client, Base64.getDecoder().decode(cloudSigningKeyBase64));
    }

    /**
     * Constructor. Designed for usage with custom PureStorage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param storage PureStorage
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     */
    public PureContext(String appToken,
                       String akBase64,
                       String buppkBase64,
                       String hpkBase64,
                       PureStorage storage,
                       String appSecretKey,
                       String servicePublicKey,
                       Map<String, List<String>> externalPublicKeys) {
        this(appToken, akBase64,buppkBase64, hpkBase64, storage, appSecretKey, servicePublicKey,  externalPublicKeys, "https://api.virgilsecurity.com/phe/v1" /* FIXME */);
    }

    /**
     * Constructor. Designed for usage with custom PureStorage
     * @param appToken Application token
     * @param akBase64 Authentication symmetric key in base64 string
     * @param buppkBase64 Backup public key in base64 string
     * @param hpkBase64 Password hashes backup public key in base64 string
     * @param storage PureStorage
     * @param appSecretKey App secret key
     * @param servicePublicKey Service public key
     * @param externalPublicKeys external public keys that will be added during encryption by default. Map key is dataId, value is list of base64 public keys
     * @param serviceAddress Service address
     */
    public PureContext(String appToken,
                       String akBase64,
                       String buppkBase64,
                       String hpkBase64,
                       PureStorage storage,
                       String appSecretKey,
                       String servicePublicKey,
                       Map<String, List<String>> externalPublicKeys,
                       String serviceAddress) {
        if (appSecretKey == null || appSecretKey.isEmpty()) {
            throw new NullPointerException();
        }
        if (servicePublicKey == null || servicePublicKey.isEmpty()) {
            throw new NullPointerException();
        }
        if (storage == null) {
            throw new NullPointerException();
        }

        this.externalPublicKeys = externalPublicKeys;
        this.ak = Base64.getDecoder().decode(akBase64);
        this.buppk = Base64.getDecoder().decode(buppkBase64);
        this.hpk = Base64.getDecoder().decode(hpkBase64);
        this.appSecretKey = appSecretKey;
        this.servicePublicKey = servicePublicKey;
        this.client = new HttpPureClient(appToken, serviceAddress);
        this.storage = storage;
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
    public String getUpdateToken() {
        return updateToken;
    }
    /**
     * Sets Update token
     */
    public void setUpdateToken(String updateToken) {
        this.updateToken = updateToken;
    }
    /**
     * Returns authentication symmetric key
     * @return Authentication symmetric key
     */
    public byte[] getAk() {
        return ak;
    }
    /**
     * Returns backup public key
     * @return Backup public key
     */
    public byte[] getBuppk() {
        return buppk;
    }
    /**
     * Returns password hashes backup public key
     * @return Password hashes backup public key
     */
    public byte[] getHpk() {
        return hpk;
    }
    /**
     * Returns app secret key
     * @return App secret key
     */
    public String getAppSecretKey() {
        return appSecretKey;
    }
    /**
     * Returns service public key
     * @return Service public key
     */
    public String getServicePublicKey() {
        return servicePublicKey;
    }
    /**
     * Returns http client
     * @return http client
     */
    public HttpPureClient getClient() {
        return client;
    }
    /**
     * Returns external public keys
     * @return external public keys
     */
    public Map<String, List<String>> getExternalPublicKeys() {
        return externalPublicKeys;
    }
}
