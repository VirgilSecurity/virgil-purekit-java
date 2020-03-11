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

package com.virgilsecurity.purekit.model;

import com.virgilsecurity.purekit.utils.ValidationUtils;

import java.util.Date;

/**
 * Grant key
 */
public class GrantKey {
    private final String userId;
    private final byte[] keyId;
    private final int recordVersion;
    private final byte[] encryptedGrantKeyWrap;
    private final byte[] encryptedGrantKeyBlob;
    private final Date creationDate;
    private final Date expirationDate;

    /**
     * Constructor
     *
     * @param userId user id
     * @param keyId key id
     * @param recordVersion record version
     * @param encryptedGrantKeyWrap encryptedGrantKeyWrape
     * @param encryptedGrantKeyBlob encryptedGrantKeyBlob
     * @param creationDate creation date
     * @param expirationDate expiration date
     */
    public GrantKey(String userId,
                    byte[] keyId,
                    int recordVersion,
                    byte[] encryptedGrantKeyWrap,
                    byte[] encryptedGrantKeyBlob,
                    Date creationDate,
                    Date expirationDate) {
        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(keyId, "keyId");
        ValidationUtils.checkNullOrEmpty(encryptedGrantKeyWrap, "encryptedGrantKeyWrap");
        ValidationUtils.checkNullOrEmpty(encryptedGrantKeyBlob, "encryptedGrantKeyBlob");
        ValidationUtils.checkNull(creationDate, "creationDate");
        ValidationUtils.checkNull(expirationDate, "expirationDate");

        this.userId = userId;
        this.keyId = keyId;
        this.recordVersion = recordVersion;
        this.encryptedGrantKeyWrap = encryptedGrantKeyWrap;
        this.encryptedGrantKeyBlob = encryptedGrantKeyBlob;
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
     * Returns record version
     *
     * @return record version
     */
    public int getRecordVersion() {
        return recordVersion;
    }

    /**
     * Returns key wrap
     *
     * @return key wrap
     */
    public byte[] getEncryptedGrantKeyWrap() {
        return encryptedGrantKeyWrap;
    }

    /**
     * Returns key blod
     *
     * @return key blob
     */
    public byte[] getEncryptedGrantKeyBlob() {
        return encryptedGrantKeyBlob;
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
