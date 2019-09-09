package com.virgilsecurity.purekit.pure;

public class PureContext {
    public PureStorage getStorage() {
        return storage;
    }

    public void setStorage(PureStorage storage) {
        this.storage = storage;
    }

    public String getAuthToken() {
        return authToken;
    }

    public void setAuthToken(String authToken) {
        this.authToken = authToken;
    }

    public byte[] getAk() {
        return ak;
    }

    public void setAk(byte[] ak) {
        this.ak = ak;
    }

    public byte[] getBuppk() {
        return buppk;
    }

    public void setBuppk(byte[] buppk) {
        this.buppk = buppk;
    }

    public byte[] getHpk() {
        return hpk;
    }

    public void setHpk(byte[] hpk) {
        this.hpk = hpk;
    }

    public String getAppSecretKey() {
        return appSecretKey;
    }

    public void setAppSecretKey(String appSecretKey) {
        this.appSecretKey = appSecretKey;
    }

    public String getServicePublicKey() {
        return servicePublicKey;
    }

    public void setServicePublicKey(String servicePublicKey) {
        this.servicePublicKey = servicePublicKey;
    }

    public String getUpdateToken() {
        return updateToken;
    }

    public void setUpdateToken(String updateToken) {
        this.updateToken = updateToken;
    }

    private PureStorage storage;
    private String authToken;
    private byte[] ak;
    private byte[] buppk;
    private byte[] hpk;
    private String appSecretKey;
    private String servicePublicKey;
    private String updateToken;
    private String serviceAddress;

    public String getServiceAddress() {
        return serviceAddress;
    }

    public void setServiceAddress(String serviceAddress) {
        this.serviceAddress = serviceAddress;
    }
}
