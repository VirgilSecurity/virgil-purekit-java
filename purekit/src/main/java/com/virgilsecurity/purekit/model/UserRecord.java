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

/**
 * User record
 */
public class UserRecord {

    private final String userId;
    private final byte[] pheRecord;
    private final int recordVersion;
    private final byte[] upk;
    private final byte[] encryptedUsk;
    private final byte[] encryptedUskBackup;
    private final byte[] backupPwdHash;
    private final byte[] passwordRecoveryWrap;
    private final byte[] passwordRecoveryBlob;

    /**
     * Instantiates UserRecord.
     *
     * @param userId User Id.
     * @param pheRecord PHE record.
     * @param recordVersion Phe record version.
     * @param upk User public key.
     * @param encryptedUsk Encrypted user secret key.
     * @param encryptedUskBackup Encrypted for backup user secret key.
     * @param backupPwdHash Encrypted for backup user password hash.
     * @param passwordRecoveryWrap Password recovery wrap.
     * @param passwordRecoveryBlob Password recovery blob.
     */
    public UserRecord(String userId, byte[] pheRecord, int recordVersion, byte[] upk,
                      byte[] encryptedUsk, byte[] encryptedUskBackup, byte[] backupPwdHash,
                      byte[] passwordRecoveryWrap, byte[] passwordRecoveryBlob) {
        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(pheRecord, "pheRecord");
        ValidationUtils.checkNullOrEmpty(upk, "upk");
        ValidationUtils.checkNullOrEmpty(encryptedUsk, "encryptedUsk");
        ValidationUtils.checkNullOrEmpty(encryptedUskBackup, "encryptedUskBackup");
        ValidationUtils.checkNullOrEmpty(backupPwdHash, "backupPwdHash");
        ValidationUtils.checkNullOrEmpty(passwordRecoveryWrap, "passwordRecoveryWrap");
        ValidationUtils.checkNullOrEmpty(passwordRecoveryBlob, "passwordRecoveryBlob");

        this.userId = userId;
        this.pheRecord = pheRecord;
        this.recordVersion = recordVersion;
        this.upk = upk;
        this.encryptedUsk = encryptedUsk;
        this.encryptedUskBackup = encryptedUskBackup;
        this.backupPwdHash = backupPwdHash;
        this.passwordRecoveryWrap = passwordRecoveryWrap;
        this.passwordRecoveryBlob = passwordRecoveryBlob;
    }

    /**
     * Return user id.
     *
     * @return User id.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Returns phe record.
     *
     * @return PHE record.
     */
    public byte[] getPheRecord() {
        return pheRecord;
    }

    /**
     * Returns phe record version.
     *
     * @return PHE record version.
     */
    public int getRecordVersion() {
        return recordVersion;
    }

    /**
     * Returns user public key.
     *
     * @return User public key.
     */
    public byte[] getUpk() {
        return upk;
    }

    /**
     * Returns encrypted user secret key.
     *
     * @return Encrypted user secret key.
     */
    public byte[] getEncryptedUsk() {
        return encryptedUsk;
    }

    /**
     * Return encrypted for backup user secret key.
     *
     * @return Encrypted for backup user secret key.
     */
    public byte[] getEncryptedUskBackup() {
        return encryptedUskBackup;
    }

    /**
     * Returns encrypted for backup user password hash.
     *
     * @return Encrypted for backup user password hash.
     */
    public byte[] getBackupPwdHash() {
        return backupPwdHash;
    }

    /**
     * Returns password recovery wrap
     *
     * @return password recovery wrap
     */
    public byte[] getPasswordRecoveryWrap() {
        return passwordRecoveryWrap;
    }

    /**
     * Returns password recovery blob
     *
     * @return password recovery blob
     */
    public byte[] getPasswordRecoveryBlob() {
        return passwordRecoveryBlob;
    }
}