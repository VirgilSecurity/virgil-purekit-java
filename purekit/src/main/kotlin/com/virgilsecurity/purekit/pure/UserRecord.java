package com.virgilsecurity.purekit.pure;

public class UserRecord {
    private String userId;
    private byte[] pheRecord;
    private int pheRecordVersion;
    private byte[] upk;
    private byte[] encryptedUsk;
    private byte[] encryptedPwdHash;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public byte[] getPheRecord() {
        return pheRecord;
    }

    public void setPheRecord(byte[] pheRecord) {
        this.pheRecord = pheRecord;
    }

    public int getPheRecordVersion() {
        return pheRecordVersion;
    }

    public void setPheRecordVersion(int pheRecordVersion) {
        this.pheRecordVersion = pheRecordVersion;
    }

    public byte[] getUpk() {
        return upk;
    }

    public void setUpk(byte[] upk) {
        this.upk = upk;
    }

    public byte[] getEncryptedUsk() {
        return encryptedUsk;
    }

    public void setEncryptedUsk(byte[] encryptedUsk) {
        this.encryptedUsk = encryptedUsk;
    }

    public byte[] getEncryptedPwdHash() {
        return encryptedPwdHash;
    }

    public void setEncryptedPwdHash(byte[] encryptedPwdHash) {
        this.encryptedPwdHash = encryptedPwdHash;
    }
}