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

import com.virgilsecurity.crypto.foundation.KeyMaterialRng;
import com.virgilsecurity.purekit.pure.exception.PureCryptoException;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * Generate nonrotatable secrets from 1 master secret
 */
public class NonrotatableSecretsGenerator {
    private static final int NONROTATABLE_MASTER_SECRET_LENGTH = 32;
    private static final int AK_LENGTH = 32;

    /**
     * Generate nonrotatable secrets from 1 master secret
     *
     * @param masterSecret master secret
     *
     * @return NonrotatableSecrets
     *
     * @throws PureException PureException
     */
    public static NonrotatableSecrets generateSecrets(byte[] masterSecret) throws PureException {
        if (masterSecret.length != NONROTATABLE_MASTER_SECRET_LENGTH) {
            throw new PureLogicException(PureLogicException.ErrorStatus.NONROTABLE_MASTER_SECRET_INVALID_LENGTH);
        }

        KeyMaterialRng rng = new KeyMaterialRng();

        rng.resetKeyMaterial(masterSecret);

        byte[] ak = rng.random(AK_LENGTH);

        VirgilCrypto crypto = new VirgilCrypto(rng);

        VirgilKeyPair vskp;
        VirgilKeyPair oskp;
        try {
            vskp = crypto.generateKeyPair();
            oskp = crypto.generateKeyPair();
        } catch (CryptoException e) {
            throw new PureCryptoException(e);
        }

        return new NonrotatableSecrets(ak, vskp, oskp);
    }
}
