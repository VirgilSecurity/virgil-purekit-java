package com.virgilsecurity.purekit.pure;

public class CellKey {
    public byte[] getCpk() {
        return cpk;
    }

    public void setCpk(byte[] cpk) {
        this.cpk = cpk;
    }

    public byte[] getEncryptedCsk() {
        return encryptedCsk;
    }

    public void setEncryptedCsk(byte[] encryptedCsk) {
        this.encryptedCsk = encryptedCsk;
    }

    private byte[] cpk;
    private byte[] encryptedCsk;
}
