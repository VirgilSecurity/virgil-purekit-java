/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

import com.virgilsecurity.crypto.foundation.Aes256Gcm;
import com.virgilsecurity.crypto.foundation.AuthEncryptAuthEncryptResult;
import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.foundation.KeyRecipientInfo;
import com.virgilsecurity.crypto.foundation.KeyRecipientInfoList;
import com.virgilsecurity.crypto.foundation.MessageInfo;
import com.virgilsecurity.crypto.foundation.MessageInfoDerSerializer;
import com.virgilsecurity.crypto.foundation.MessageInfoEditor;
import com.virgilsecurity.crypto.foundation.RecipientCipher;
import com.virgilsecurity.crypto.foundation.Sha512;
import com.virgilsecurity.crypto.foundation.SignerInfo;
import com.virgilsecurity.crypto.foundation.SignerInfoList;
import com.virgilsecurity.crypto.phe.PheCipher;
import com.virgilsecurity.crypto.phe.PheException;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.KeyPairType;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

class PureCrypto {

    private final VirgilCrypto crypto;
    //TODO pheCipher is not closed
    private final PheCipher pheCipher;

    PureCrypto(VirgilCrypto crypto) throws PureCryptoException {
        this.crypto = crypto;

        try {
            this.pheCipher = new PheCipher();
            this.pheCipher.setRandom(crypto.getRng());
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    PureCryptoData encryptCellKey(byte[] plainTextData,
                                  Collection<VirgilPublicKey> recipients,
                                  VirgilPrivateKey signingKey)
            throws PureCryptoException {

        try (Aes256Gcm aesGcm = new Aes256Gcm();
             RecipientCipher cipher = new RecipientCipher();
             Sha512 sha512 = new Sha512()) {

            cipher.setEncryptionCipher(aesGcm);
            cipher.setRandom(crypto.getRng());

            cipher.addSigner(signingKey.getIdentifier(), signingKey.getPrivateKey());

            //TODO add null check for recipients
            for (VirgilPublicKey key : recipients) {
                cipher.addKeyRecipient(key.getIdentifier(), key.getPublicKey());
            }

            cipher.setSignerHash(sha512);
            cipher.startSignedEncryption(plainTextData.length);

            byte[] cms = cipher.packMessageInfo();

            byte[] body1 = cipher.processEncryption(plainTextData);
            byte[] body2 = cipher.finishEncryption();
            byte[] body3 = cipher.packMessageInfoFooter();

            byte[] body = concat(concat(body1, body2), body3);

            return new PureCryptoData(cms, body);
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] decryptCellKey(PureCryptoData data, VirgilPrivateKey privateKey, VirgilPublicKey verifyingKey)
        throws PureCryptoException {

        try (RecipientCipher cipher = new RecipientCipher()) {

            cipher.setRandom(crypto.getRng());

            cipher.startVerifiedDecryptionWithKey(privateKey.getIdentifier(),
                    privateKey.getPrivateKey(),
                    data.getCms(), new byte[0]);

            byte[] body1 = cipher.processDecryption(data.getBody());
            byte[] body2 = cipher.finishDecryption();

            if (!cipher.isDataSigned()) {
                throw new PureCryptoException(PureCryptoException.ErrorStatus.SIGNATURE_IS_ABSENT);
            }

            SignerInfoList signerInfoList = cipher.signerInfos();

            if (!signerInfoList.hasItem() && signerInfoList.hasNext()) {
                throw new PureCryptoException(PureCryptoException.ErrorStatus.SIGNER_IS_ABSENT);
            }

            SignerInfo signerInfo = signerInfoList.item();

            if (!Arrays.equals(signerInfo.signerId(), verifyingKey.getIdentifier())) {
                throw new PureCryptoException(PureCryptoException.ErrorStatus.SIGNER_IS_ABSENT);
            }

            if (!cipher.verifySignerInfo(signerInfo, verifyingKey.getPublicKey())) {
                throw new PureCryptoException(
                    PureCryptoException.ErrorStatus.SIGNATURE_VERIFICATION_FAILED
                );
            }

            return concat(body1, body2);
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] addRecipientsToCellKey(byte[] cms,
                                  VirgilPrivateKey privateKey,
                                  Collection<VirgilPublicKey> publicKeys)
        throws PureCryptoException {

        try (MessageInfoEditor infoEditor = new MessageInfoEditor()) {
            infoEditor.setRandom(crypto.getRng());

            infoEditor.unpack(cms);
            infoEditor.unlock(privateKey.getIdentifier(), privateKey.getPrivateKey());

            for (VirgilPublicKey publicKey : publicKeys) {
                infoEditor.addKeyRecipient(publicKey.getIdentifier(), publicKey.getPublicKey());
            }

            return infoEditor.pack();
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] deleteRecipientsFromCellKey(byte[] cms, Collection<VirgilPublicKey> publicKeys)
        throws PureCryptoException {

        try (MessageInfoEditor infoEditor = new MessageInfoEditor()) {
            infoEditor.setRandom(this.crypto.getRng());

            infoEditor.unpack(cms);

            //TODO null check for publicKeys
            for (VirgilPublicKey publicKey : publicKeys) {
                infoEditor.removeKeyRecipient(publicKey.getIdentifier());
            }

            return infoEditor.pack();
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    // FIXME: Should be replaced with Set<byte[]> but such set doesn't work properly
    Set<ByteBuffer> extractPublicKeysIdsFromCellKey(byte[] cms) throws PureCryptoException {
        HashSet<ByteBuffer> publicKeysIds = new HashSet<>();

        try (MessageInfoDerSerializer messageInfoSerializer = new MessageInfoDerSerializer()) {
            messageInfoSerializer.setupDefaults();
            try (MessageInfo messageInfo = messageInfoSerializer.deserialize(cms)) {
                KeyRecipientInfoList keyRecipientInfoList = messageInfo.keyRecipientInfoList();

                while (keyRecipientInfoList != null && keyRecipientInfoList.hasItem()) {
                    try (KeyRecipientInfo keyRecipientInfo = keyRecipientInfoList.item()) {
                        publicKeysIds.add(ByteBuffer.wrap(keyRecipientInfo.recipientId()));
                    }

                    if (keyRecipientInfoList.hasNext()) {
                        keyRecipientInfoList = keyRecipientInfoList.next();
                    }
                    else {
                        keyRecipientInfoList = null;
                    }
                }

                return publicKeysIds;
            }
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    static final int DERIVED_SECRET_LENGTH = 44;

    byte[] generateSymmetricOneTimeKey() {
        return crypto.generateRandomData(DERIVED_SECRET_LENGTH);
    }

    byte[] computeSymmetricKeyId(byte[] key) {
        return crypto.computeHash(key, HashAlgorithm.SHA512);
    }

    byte[] encryptSymmetricWithOneTimeKey(byte[] plainText, byte[] ad, byte[] key) throws PureCryptoException {
        try (Aes256Gcm aes256Gcm = new Aes256Gcm()) {

            aes256Gcm.setKey(Arrays.copyOfRange(key, 0, aes256Gcm.getKeyLen()));
            aes256Gcm.setNonce(Arrays.copyOfRange(key, aes256Gcm.getKeyLen(), aes256Gcm.getKeyLen() + aes256Gcm.getNonceLen()));

            AuthEncryptAuthEncryptResult authEncryptAuthEncryptResult = aes256Gcm.authEncrypt(plainText, ad);

            return concat(authEncryptAuthEncryptResult.getOut(), authEncryptAuthEncryptResult.getTag());
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] decryptSymmetricWithOneTimeKey(byte[] cipherText, byte[] ad, byte[] key) throws PureCryptoException {
        try (Aes256Gcm aes256Gcm = new Aes256Gcm()) {

            aes256Gcm.setKey(Arrays.copyOfRange(key, 0, aes256Gcm.getKeyLen()));
            aes256Gcm.setNonce(Arrays.copyOfRange(key, aes256Gcm.getKeyLen(), aes256Gcm.getKeyLen() + aes256Gcm.getNonceLen()));

            return aes256Gcm.authDecrypt(cipherText, ad, new byte[0]);
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] encryptSymmetricWithNewNonce(byte[] plainText, byte[] ad, byte[] key) throws PureCryptoException {
        try {
            return pheCipher.authEncrypt(plainText, ad, key);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] decryptSymmetricWithNewNonce(byte[] cipherText, byte[] ad, byte[] key) throws PureCryptoException {
        try {
            return pheCipher.authDecrypt(cipherText, ad, key);
        }
        catch (PheException e) {
            throw new PureCryptoException(e);
        }
    }

    private byte[] concat(byte[] body1, byte[] body2) {
        byte[] body = new byte[body1.length + body2.length];
        System.arraycopy(body1, 0, body, 0, body1.length);
        System.arraycopy(body2, 0, body, body1.length, body2.length);

        return body;
    }

    VirgilKeyPair generateUserKey() throws PureCryptoException {
        try {
            return crypto.generateKeyPair(KeyPairType.ED25519);
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
    }

    VirgilKeyPair generateRoleKey() throws PureCryptoException {
        try {
            return crypto.generateKeyPair(KeyPairType.ED25519);
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
    }

    VirgilKeyPair generateCellKey() throws PureCryptoException {
        try {
            return crypto.generateKeyPair(KeyPairType.ED25519);
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
    }

    VirgilKeyPair importPrivateKey(byte[] privateKey) throws PureCryptoException {
        try {
            return crypto.importPrivateKey(privateKey);
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
    }

    VirgilPublicKey importPublicKey(byte[] publicKey) throws PureCryptoException {
        try {
            return crypto.importPublicKey(publicKey);
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] exportPublicKey(VirgilPublicKey publicKey) throws PureCryptoException {
        try {
            return crypto.exportPublicKey(publicKey);
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] exportPrivateKey(VirgilPrivateKey privateKey) throws PureCryptoException {
        try {
            return crypto.exportPrivateKey(privateKey);
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] encryptForBackup(byte[] plainText, VirgilPublicKey encryptKey, VirgilPrivateKey signingKey) throws PureCryptoException {
        try {
            return crypto.authEncrypt(plainText, signingKey, encryptKey);
            //TODO CryptoException could be used here
        } catch (SigningException | EncryptionException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] decryptBackup(byte[] cipherText, VirgilPrivateKey decryptKey, VirgilPublicKey verifyKey) throws PureCryptoException {
        try {
            return crypto.authDecrypt(cipherText, decryptKey, verifyKey);
            //TODO CryptoException could be used here
        } catch (VerificationException | DecryptionException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] encryptData(byte[] plainText, List<VirgilPublicKey> publicKeys, VirgilPrivateKey privateKey) throws PureCryptoException {
        try {
            return crypto.authEncrypt(plainText, privateKey, publicKeys);
            //TODO CryptoException could be used here
        } catch (EncryptionException | SigningException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] decryptData(byte[] cipherText, VirgilPrivateKey privateKey, VirgilPublicKey publicKey) throws PureCryptoException {
        try {
            return crypto.authDecrypt(cipherText, privateKey, publicKey);
            //TODO CryptoException could be used here
        } catch (VerificationException | DecryptionException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] encryptRolePrivateKey(byte[] plainText, VirgilPublicKey publicKey, VirgilPrivateKey privateKey) throws PureCryptoException {
        try {
            return crypto.authEncrypt(plainText, privateKey, publicKey);
            //TODO CryptoException could be used here
        } catch (SigningException | EncryptionException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] decryptRolePrivateKey(byte[] plainText, VirgilPrivateKey privateKey, VirgilPublicKey publicKey) throws PureCryptoException {
        try {
            return crypto.authDecrypt(plainText, privateKey, publicKey);
            //TODO CryptoException could be used here
        } catch (VerificationException | DecryptionException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] computePasswordHash(String password) {
        return crypto.computeHash(password.getBytes(), HashAlgorithm.SHA512);
    }
}
