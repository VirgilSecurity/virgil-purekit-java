/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import com.virgilsecurity.crypto.foundation.*;
import com.virgilsecurity.crypto.phe.PheCipher;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;

class PureCrypto {

    private final VirgilCrypto crypto;
    private final PheCipher pheCipher;

    PureCrypto(VirgilCrypto crypto) {
        this.crypto = crypto;
        this.pheCipher = new PheCipher();
        this.pheCipher.setRandom(crypto.getRng());
    }

    PureCryptoData encryptCellKey(byte[] plainTextData,
                                  VirgilPrivateKey signingKey,
                                  Collection<VirgilPublicKey> recipients)
            throws PureCryptoException {

        try (Aes256Gcm aesGcm = new Aes256Gcm();
             RecipientCipher cipher = new RecipientCipher()) {

            cipher.setEncryptionCipher(aesGcm);
            cipher.setRandom(crypto.getRng());

            cipher.addSigner(signingKey.getIdentifier(), signingKey.getPrivateKey());

            for (VirgilPublicKey key : recipients) {
                cipher.addKeyRecipient(key.getIdentifier(), key.getPublicKey());
            }

            cipher.setSignerHash(new Sha512());
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

    byte[] decryptCellKey(PureCryptoData data, VirgilPublicKey verifyingKey, VirgilPrivateKey privateKey)
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
                // FIXME: KeyRecipientInfoList is also autoclosable
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
            catch (FoundationException e) {
                throw new PureCryptoException(e);
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

    byte[] encryptSymmetricOneTimeKey(byte[] plainText, byte[] ad, byte[] key) throws PureCryptoException {
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

    byte[] decryptSymmetricOneTimeKey(byte[] cipherText, byte[] ad, byte[] key) throws PureCryptoException {
        try (Aes256Gcm aes256Gcm = new Aes256Gcm()) {

            aes256Gcm.setKey(Arrays.copyOfRange(key, 0, aes256Gcm.getKeyLen()));
            aes256Gcm.setNonce(Arrays.copyOfRange(key, aes256Gcm.getKeyLen(), aes256Gcm.getKeyLen() + aes256Gcm.getNonceLen()));

            return aes256Gcm.authDecrypt(cipherText, ad, new byte[0]);
        }
        catch (FoundationException e) {
            throw new PureCryptoException(e);
        }
    }

    byte[] encryptSymmetricNewNonce(byte[] plainText, byte[] ad, byte[] key) {
        return pheCipher.authEncrypt(plainText, ad, key);
    }

    byte[] decryptSymmetricNewNonce(byte[] cipherText, byte[] ad, byte[] key) {
        return pheCipher.authDecrypt(cipherText, ad, key);
    }

    private byte[] concat(byte[] body1, byte[] body2) {
        byte[] body = new byte[body1.length + body2.length];
        System.arraycopy(body1, 0, body, 0, body1.length);
        System.arraycopy(body2, 0, body, body1.length, body2.length);

        return body;
    }
}
