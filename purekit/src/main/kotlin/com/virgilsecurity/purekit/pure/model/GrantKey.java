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

package com.virgilsecurity.purekit.pure.model;

import java.util.Date;

/**
 * Grant key
 */
public class GrantKey {
    private final String userId;
    private final byte[] keyId;
    private final byte[] encryptedGrantKey;
    private final Date creationDate;
    private final Date expirationDate;

    /**
     * Constructor
     *
     * @param userId user id
     * @param keyId key id
     * @param encryptedGrantKey encrypted grant key
     * @param creationDate creation date
     * @param expirationDate expiration date
     */
    public GrantKey(String userId, byte[] keyId, byte[] encryptedGrantKey, Date creationDate, Date expirationDate) {
        this.userId = userId;
        this.keyId = keyId;
        this.encryptedGrantKey = encryptedGrantKey;
        this.creationDate = creationDate;
        this.expirationDate = expirationDate;
    }

    /**
     * Returns user id
     *
     * @return user id
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Returns key id
     *
     * @return key id
     */
    public byte[] getKeyId() {
        return keyId;
    }

    /**
     * Returns encrypted grant key
     *
     * @return encrypted grant key
     */
    public byte[] getEncryptedGrantKey() {
        return encryptedGrantKey;
    }

    /**
     * Returns expiration date
     *
     * @return expiration date
     */
    public Date getExpirationDate() {
        return expirationDate;
    }

    /**
     * Returns creation date
     *
     * @return creation date
     */
    public Date getCreationDate() {
        return creationDate;
    }
}
