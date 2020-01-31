package com.virgilsecurity.purekit.pure.model;

import java.util.Date;

public class GrantKey {
    private final String userId;
    private final byte[] keyId;
    private final byte[] encryptedGrantKey;
    private final Date creationDate;
    private final Date expirationDate;

    public GrantKey(String userId, byte[] keyId, byte[] encryptedGrantKey, Date creationDate, Date expirationDate) {
        this.userId = userId;
        this.keyId = keyId;
        this.encryptedGrantKey = encryptedGrantKey;
        this.creationDate = creationDate;
        this.expirationDate = expirationDate;
    }

    public String getUserId() {
        return userId;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public byte[] getEncryptedGrantKey() {
        return encryptedGrantKey;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public Date getCreationDate() {
        return creationDate;
    }
}
