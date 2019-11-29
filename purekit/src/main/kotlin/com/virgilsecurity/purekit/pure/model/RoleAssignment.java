package com.virgilsecurity.purekit.pure.model;

public class RoleAssignment {

    public String getRoleName() {
        return roleName;
    }

    public byte[] getPublicKeyId() {
        return publicKeyId;
    }

    public byte[] getEncryptedRsk() {
        return encryptedRsk;
    }

    public String getUserId() {
        return userId;
    }

    private String roleName;
    private String userId;
    private byte[] publicKeyId;
    private byte[] encryptedRsk;

    public RoleAssignment(String roleName, String userId, byte[] publicKeyId, byte[] encryptedRsk) {
        this.roleName = roleName;
        this.userId = userId;
        this.publicKeyId = publicKeyId;
        this.encryptedRsk = encryptedRsk;
    }
}
