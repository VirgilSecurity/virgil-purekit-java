package com.virgilsecurity.purekit.pure;

public class UserRecord {
    private String userId;
    private byte[] pheRecord;
    private int pheRecordVersion;
    private byte[] upk;
    private byte[] encryptedUsk;
    private byte[] encryptedUskBackup;
    private byte[] encryptedPwdHash;

    public UserRecord(String userId, byte[] pheRecord, int pheRecordVersion, byte[] upk, byte[] encryptedUsk, byte[] encryptedUskBackup, byte[] encryptedPwdHash) {
        this.userId = userId;
        this.pheRecord = pheRecord;
        this.pheRecordVersion = pheRecordVersion;
        this.upk = upk;
        this.encryptedUsk = encryptedUsk;
        this.encryptedUskBackup = encryptedUskBackup;
        this.encryptedPwdHash = encryptedPwdHash;
    }

    public String getUserId() {
        return userId;
    }

    public byte[] getPheRecord() {
        return pheRecord;
    }

    public int getPheRecordVersion() {
        return pheRecordVersion;
    }

    public byte[] getUpk() {
        return upk;
    }

    public byte[] getEncryptedUsk() {
        return encryptedUsk;
    }

    public byte[] getEncryptedUskBackup() {
        return encryptedUskBackup;
    }

    public byte[] getEncryptedPwdHash() {
        return encryptedPwdHash;
    }
}