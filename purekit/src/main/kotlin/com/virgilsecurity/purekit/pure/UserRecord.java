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

/**
 * User record
 */
public class UserRecord {
    private String userId;
    private byte[] pheRecord;
    private int pheRecordVersion;
    private byte[] upk;
    private byte[] encryptedUsk;
    private byte[] encryptedUskBackup;
    private byte[] encryptedPwdHash;

    /**
     * Constructor
     * @param userId userId
     * @param pheRecord phe record
     * @param pheRecordVersion phe record version
     * @param upk user public key
     * @param encryptedUsk encrypted user secret key
     * @param encryptedUskBackup encrypted for backup user secret key
     * @param encryptedPwdHash encrypted for backup user password hash
     */
    public UserRecord(String userId, byte[] pheRecord, int pheRecordVersion, byte[] upk, byte[] encryptedUsk, byte[] encryptedUskBackup, byte[] encryptedPwdHash) {
        this.userId = userId;
        this.pheRecord = pheRecord;
        this.pheRecordVersion = pheRecordVersion;
        this.upk = upk;
        this.encryptedUsk = encryptedUsk;
        this.encryptedUskBackup = encryptedUskBackup;
        this.encryptedPwdHash = encryptedPwdHash;
    }

    /**
     * Return user id
     * @return User id
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Returns phe record
     * @return PHE record
     */
    public byte[] getPheRecord() {
        return pheRecord;
    }

    /**
     * Returns phe record version
     * @return PHE record version
     */
    public int getPheRecordVersion() {
        return pheRecordVersion;
    }

    /**
     * Returns user public key
     * @return User public key
     */
    public byte[] getUpk() {
        return upk;
    }

    /**
     * Returns encrypted user secret key
     * @return Encrypted user secret key
     */
    public byte[] getEncryptedUsk() {
        return encryptedUsk;
    }

    /**
     * Return encrypted for backup user secret key
     * @return Encrypted for backup user secret key
     */
    public byte[] getEncryptedUskBackup() {
        return encryptedUskBackup;
    }

    /**
     * Returns encrypted for backup user password hash
     * @return Encrypted for backup user password hash
     */
    public byte[] getEncryptedPwdHash() {
        return encryptedPwdHash;
    }
}