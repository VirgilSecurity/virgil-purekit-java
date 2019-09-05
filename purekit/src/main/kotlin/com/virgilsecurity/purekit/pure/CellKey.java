package com.virgilsecurity.purekit.pure;

public class CellKey {
    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public void setEncryptedPrivateKey(byte[] encryptedPrivateKey) {
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    private byte[] publicKey;
    private byte[] encryptedPrivateKey;
}
