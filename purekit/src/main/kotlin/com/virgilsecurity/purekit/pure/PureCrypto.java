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

import com.virgilsecurity.crypto.foundation.Aes256Gcm;
import com.virgilsecurity.crypto.foundation.MessageInfoEditor;
import com.virgilsecurity.crypto.foundation.RecipientCipher;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilPrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;

import java.util.List;

class PureCrypto {
    private VirgilCrypto crypto;

    PureCrypto(VirgilCrypto crypto) {
        this.crypto = crypto;
    }

    private static byte[] concat(byte[] body1, byte[] body2) {
        byte[] body = new byte[body1.length + body2.length];
        System.arraycopy(body1, 0, body, 0, body1.length);
        System.arraycopy(body2, 0, body, body1.length, body2.length);

        return body;
    }

    PureCryptoData encrypt(byte[] plainText, List<VirgilPublicKey> recipients) {
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

    byte[] decrypt(PureCryptoData data, VirgilPrivateKey privateKey) {
        RecipientCipher cipher = new RecipientCipher();

        cipher.setRandom(this.crypto.getRng());

        cipher.startDecryptionWithKey(privateKey.getIdentifier(), privateKey.getPrivateKey(), data.getCms());

        byte[] body1 = cipher.processDecryption(data.getBody());
        byte[] body2 = cipher.finishDecryption();

        return concat(body1, body2);
    }

    byte[] addRecipient(byte[] cms, VirgilPrivateKey privateKey, VirgilPublicKey publicKey) {
        MessageInfoEditor infoEditor = new MessageInfoEditor();
        infoEditor.setRandom(this.crypto.getRng());

        infoEditor.unpack(cms);
        infoEditor.unlock(privateKey.getIdentifier(), privateKey.getPrivateKey());

        infoEditor.addKeyRecipient(publicKey.getIdentifier(), publicKey.getPublicKey());

        return infoEditor.pack();
    }

    byte[] deleteRecipient(byte[] cms, VirgilPublicKey publicKey) {
        MessageInfoEditor infoEditor = new MessageInfoEditor();
        infoEditor.setRandom(this.crypto.getRng());

        infoEditor.unpack(cms);
        infoEditor.removeKeyRecipient(publicKey.getIdentifier());

        return infoEditor.pack();
    }
}
