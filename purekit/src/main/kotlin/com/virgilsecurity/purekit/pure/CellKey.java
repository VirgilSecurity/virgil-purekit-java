package com.virgilsecurity.purekit.pure;

public class CellKey {

    public CellKey(byte[] cpk, byte[] encryptedCskCms, byte[] encryptedCskBody) {
        this.cpk = cpk;
        this.encryptedCskCms = encryptedCskCms;
        this.encryptedCskBody = encryptedCskBody;
    }

    public byte[] getCpk() {
        return cpk;
    }

    public byte[] getEncryptedCskCms() {
        return encryptedCskCms;
    }

    public byte[] getEncryptedCskBody() {
        return encryptedCskBody;
    }

    private byte[] cpk;
    private byte[] encryptedCskCms;
    private byte[] encryptedCskBody;
}
