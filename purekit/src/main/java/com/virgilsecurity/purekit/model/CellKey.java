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

import com.virgilsecurity.purekit.utils.ValidateUtils;

/**
 * CellKey class represents encrypted asymmetric key used to encrypt data.
 */
public class CellKey {
    private final String userId;
    private final String dataId;
    private final byte[] cpk;
    private final byte[] encryptedCskCms;
    private final byte[] encryptedCskBody;

    /**
     * Instantiates CellKey.
     *
     * @param cpk Cell public key.
     * @param encryptedCskCms Encrypted cell secret key CMS.
     * @param encryptedCskBody Encrypted cell secret key body.
     */
    public CellKey(String userId, String dataId, byte[] cpk, byte[] encryptedCskCms, byte[] encryptedCskBody) {
        ValidateUtils.checkNullOrEmpty(userId, "userId");
        ValidateUtils.checkNullOrEmpty(dataId, "dataId");
        ValidateUtils.checkNullOrEmpty(cpk, "cpk");
        ValidateUtils.checkNullOrEmpty(encryptedCskCms, "encryptedCskCms");
        ValidateUtils.checkNullOrEmpty(encryptedCskBody, "encryptedCskBody");

        this.userId = userId;
        this.dataId = dataId;
        this.cpk = cpk;
        this.encryptedCskCms = encryptedCskCms;
        this.encryptedCskBody = encryptedCskBody;
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
     * Returns data id
     *
     * @return data id
     */
    public String getDataId() {
        return dataId;
    }

    /**
     * Cell public key.
     *
     * @return Cell public key.
     */
    public final byte[] getCpk() {
        return cpk;
    }

    /**
     * Encrypted cell secret key CMS.
     *
     * @return Encrypted cell secret key CMS.
     */
    public final byte[] getEncryptedCskCms() {
        return encryptedCskCms;
    }

    /**
     * Encrypted cell secret key body.
     *
     * @return Encrypted cell secret key body.
     */
    public final byte[] getEncryptedCskBody() {
        return encryptedCskBody;
    }
}
