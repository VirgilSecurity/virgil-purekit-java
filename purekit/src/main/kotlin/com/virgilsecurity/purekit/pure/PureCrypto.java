package com.virgilsecurity.purekit.pure;

import com.virgilsecurity.crypto.foundation.Aes256Gcm;
import com.virgilsecurity.crypto.foundation.MessageInfoEditor;
import com.virgilsecurity.crypto.foundation.RecipientCipher;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;

import java.util.List;

public class PureCrypto {
    private VirgilCrypto crypto;

    public PureCrypto(VirgilCrypto crypto) {
        this.crypto = crypto;
    }

    private static byte[] concat(byte[] body1, byte[] body2) {
        byte[] body = new byte[body1.length + body2.length];
        System.arraycopy(body1, 0, body, 0, body1.length);
        System.arraycopy(body2, 0, body, body1.length, body2.length);

        return body;
    }

    public PureCryptoData encrypt(byte[] plainText, List<VirgilPublicKey> recipients) {
        Aes256Gcm aesGcm = new Aes256Gcm();
        RecipientCipher cipher = new RecipientCipher();

        cipher.setEncryptionCipher(aesGcm);
        cipher.setRandom(this.crypto.getRng());

        for (VirgilPublicKey key: recipients) {
            cipher.addKeyRecipient(key.getIdentifier(), key.getPublicKey());
        }

        cipher.startEncryption();

        byte[] cms = cipher.packMessageInfo();

        byte[] body1 = cipher.processEncryption(plainText);
        byte[] body2 = cipher.finishEncryption();

        byte[] body = concat(body1, body2);

        return new PureCryptoData(cms, body);
    }

    public byte[] decrypt(PureCryptoData data, VirgilPrivateKey privateKey) {
        RecipientCipher cipher = new RecipientCipher();

        cipher.setRandom(this.crypto.getRng());

        cipher.startDecryptionWithKey(privateKey.getIdentifier(), privateKey.getPrivateKey(), data.getCms());

        byte[] body1 = cipher.processDecryption(data.getBody());
        byte[] body2 = cipher.finishDecryption();

        return concat(body1, body2);
    }

    public byte[] addRecipient(byte[] cms, VirgilPrivateKey privateKey, VirgilPublicKey publicKey) {
        MessageInfoEditor infoEditor = new MessageInfoEditor();
        infoEditor.setRandom(this.crypto.getRng());

        infoEditor.unpack(cms);
        infoEditor.unlock(privateKey.getIdentifier(), privateKey.getPrivateKey());

        infoEditor.addKeyRecipient(publicKey.getIdentifier(), publicKey.getPublicKey());

        return infoEditor.pack();
    }

    public byte[] deleteRecipient(byte[] cms, VirgilPublicKey publicKey) {
        MessageInfoEditor infoEditor = new MessageInfoEditor();
        infoEditor.setRandom(this.crypto.getRng());

        infoEditor.unpack(cms);
        infoEditor.removeKeyRecipient(publicKey.getIdentifier());

        return infoEditor.pack();
    }
}
