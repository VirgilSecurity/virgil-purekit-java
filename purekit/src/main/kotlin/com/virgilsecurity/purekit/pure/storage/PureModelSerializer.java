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

package com.virgilsecurity.purekit.pure.storage;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Crypto;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.pure.model.CellKey;
import com.virgilsecurity.purekit.pure.model.GrantKey;
import com.virgilsecurity.purekit.pure.model.Role;
import com.virgilsecurity.purekit.pure.model.RoleAssignment;
import com.virgilsecurity.purekit.pure.model.UserRecord;
import com.virgilsecurity.purekit.utils.ValidateUtils;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

import java.util.Date;

/**
 * Class that signs Pure models and serializes them to protobuf models
 */
public class PureModelSerializer {
    private static final int CURRENT_USER_VERSION = 1;
    private static final int CURRENT_USER_SIGNED_VERSION = 1;
    private static final int CURRENT_CELL_KEY_VERSION = 1;
    private static final int CURRENT_CELL_KEY_SIGNED_VERSION = 1;
    private static final int CURRENT_ROLE_VERSION = 1;
    private static final int CURRENT_ROLE_SIGNED_VERSION = 1;
    private static final int CURRENT_ROLE_ASSIGNMENT_VERSION = 1;
    private static final int CURRENT_ROLE_ASSIGNMENT_SIGNED_VERSION = 1;
    private static final int CURRENT_GRANT_KEY_VERSION = 1;
    private static final int CURRENT_GRANT_KEY_SIGNED_VERSION = 1;

    private final VirgilCrypto crypto;
    private final VirgilKeyPair signingKey;

    /**
     * Instantiates PureModelSerializer.
     *
     * @param crypto VirgilCrypto
     * @param signingKey Key used to sign data before sending to Virgil.
     */
    public PureModelSerializer(VirgilCrypto crypto, VirgilKeyPair signingKey) {
        ValidateUtils.checkNull(crypto, "crypto");
        ValidateUtils.checkNull(signingKey, "signingKey");

        this.crypto = crypto;
        this.signingKey = signingKey;
    }

    private byte[] generateSignature(byte[] model) throws PureStorageGenericException {
        try {
            return this.crypto.generateSignature(model, this.signingKey.getPrivateKey());
        } catch (SigningException e) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.SIGNING_EXCEPTION);
        }
    }

    private void verifySignature(byte[] signature, byte[] model) throws PureStorageException {
        boolean verified;
        try {
            verified = this.crypto.verifySignature(signature, model, this.signingKey.getPublicKey());
        } catch (VerificationException e) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.VERIFICATION_EXCEPTION);
        }

        if (!verified) {
            throw new PureStorageGenericException(
                    PureStorageGenericException.ErrorStatus.STORAGE_SIGNATURE_VERIFICATION_FAILED
            );
        }
    }

    /**
     * Signs and serializes UserRecord
     *
     * @param userRecord user record
     *
     * @return protobuf model
     *
     * @throws PureStorageException PureStorageException
     */
    public PurekitProtosV3Storage.UserRecord serializeUserRecord(UserRecord userRecord) throws PureStorageException {
        ValidateUtils.checkNull(userRecord, "userRecord");

        PurekitProtosV3Crypto.EnrollmentRecord enrollmentRecord;
        try {
            enrollmentRecord = PurekitProtosV3Crypto.EnrollmentRecord.parseFrom(userRecord.getPheRecord());
        } catch (InvalidProtocolBufferException e) {
            throw new PureStorageGenericException(PureStorageGenericException.ErrorStatus.INVALID_PROTOBUF);
        }

        byte[] userRecordSigned = PurekitProtosV3Storage.UserRecordSigned
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_USER_SIGNED_VERSION)
                .setUserId(userRecord.getUserId())
                .setPheRecordNc(enrollmentRecord.getNc())
                .setPheRecordNs(enrollmentRecord.getNs())
                .setUpk(ByteString.copyFrom(userRecord.getUpk()))
                .setEncryptedUsk(ByteString.copyFrom(userRecord.getEncryptedUsk()))
                .setEncryptedUskBackup(ByteString.copyFrom(userRecord.getEncryptedUskBackup()))
                .setBackupPwdHash(ByteString.copyFrom(userRecord.getBackupPwdHash()))
                .setPasswordRecoveryBlob(ByteString.copyFrom(userRecord.getPasswordRecoveryBlob()))
                .build()
                .toByteArray();

        byte[] signature = generateSignature(userRecordSigned);

        return PurekitProtosV3Storage.UserRecord
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_USER_VERSION)
                .setUserRecordSigned(ByteString.copyFrom(userRecordSigned))
                .setSignature(ByteString.copyFrom(signature))
                .setPheRecordT0(enrollmentRecord.getT0())
                .setPheRecordT1(enrollmentRecord.getT1())
                .setRecordVersion(userRecord.getRecordVersion())
                .setPasswordRecoveryWrap(ByteString.copyFrom(userRecord.getPasswordRecoveryWrap()))
                .build();
    }

    /**
     * Parses and verifies signature of UserRecord
     *
     * @param protobufRecord protobuf
     *
     * @return UserRecord
     *
     * @throws PureStorageException PureStorageException
     */
    public UserRecord parseUserRecord(PurekitProtosV3Storage.UserRecord protobufRecord) throws PureStorageException {
        ValidateUtils.checkNull(protobufRecord, "protobufRecord");

        verifySignature(protobufRecord.getSignature().toByteArray(), protobufRecord.getUserRecordSigned().toByteArray());

        PurekitProtosV3Storage.UserRecordSigned recordSigned;
        try {
            recordSigned = PurekitProtosV3Storage.UserRecordSigned.parseFrom(protobufRecord.getUserRecordSigned());
        } catch (InvalidProtocolBufferException e) {
            throw new PureStorageInvalidProtobufException(e);
        }

        byte[] pheRecord = PurekitProtosV3Crypto.EnrollmentRecord
                .newBuilder()
                .setNc(recordSigned.getPheRecordNc())
                .setNs(recordSigned.getPheRecordNs())
                .setT0(protobufRecord.getPheRecordT0())
                .setT1(protobufRecord.getPheRecordT1())
                .build()
                .toByteArray();

        return new UserRecord(recordSigned.getUserId(),
                pheRecord,
                protobufRecord.getRecordVersion(),
                recordSigned.getUpk().toByteArray(),
                recordSigned.getEncryptedUsk().toByteArray(),
                recordSigned.getEncryptedUskBackup().toByteArray(),
                recordSigned.getBackupPwdHash().toByteArray(),
                protobufRecord.getPasswordRecoveryWrap().toByteArray(),
                recordSigned.getPasswordRecoveryBlob().toByteArray());
    }

    /**
     * Signs and serializes CellKey
     *
     * @param cellKey CellKey
     *
     * @return protobuf record
     *
     * @throws PureStorageException PureStorageException
     */
    public PurekitProtosV3Storage.CellKey serializeCellKey(CellKey cellKey) throws PureStorageException {
        ValidateUtils.checkNull(cellKey, "cellKey");

        byte[] cellKeySigned = PurekitProtosV3Storage.CellKeySigned
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_CELL_KEY_SIGNED_VERSION)
                .setUserId(cellKey.getUserId())
                .setDataId(cellKey.getDataId())
                .setCpk(ByteString.copyFrom(cellKey.getCpk()))
                .setEncryptedCskCms(ByteString.copyFrom(cellKey.getEncryptedCskCms()))
                .setEncryptedCskBody(ByteString.copyFrom(cellKey.getEncryptedCskBody()))
                .build()
                .toByteArray();

        byte[] signature = generateSignature(cellKeySigned);

        return PurekitProtosV3Storage.CellKey
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_CELL_KEY_VERSION)
                .setCellKeySigned(ByteString.copyFrom(cellKeySigned))
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    /**
     * Parses and verifies signature of CellKey
     *
     * @param protobufRecord protobuf
     *
     * @return CellKey
     *
     * @throws PureStorageException PureStorageException
     */
    public CellKey parseCellKey(PurekitProtosV3Storage.CellKey protobufRecord) throws PureStorageException {
        ValidateUtils.checkNull(protobufRecord, "protobufRecord");

        verifySignature(protobufRecord.getSignature().toByteArray(), protobufRecord.getCellKeySigned().toByteArray());

        PurekitProtosV3Storage.CellKeySigned keySigned;
        try {
            keySigned = PurekitProtosV3Storage.CellKeySigned.parseFrom(protobufRecord.getCellKeySigned());
        } catch (InvalidProtocolBufferException e) {
            throw new PureStorageInvalidProtobufException(e);
        }

        return new CellKey(keySigned.getUserId(), keySigned.getDataId(),
                keySigned.getCpk().toByteArray(),
                keySigned.getEncryptedCskCms().toByteArray(),
                keySigned.getEncryptedCskBody().toByteArray());
    }

    /**
     * Signs and serializes Role
     *
     * @param role Role
     *
     * @return protobuf record
     *
     * @throws PureStorageException PureStorageException
     */
    public PurekitProtosV3Storage.Role serializeRole(Role role) throws PureStorageException {
        ValidateUtils.checkNull(role, "role");

        byte[] roleSigned = PurekitProtosV3Storage.RoleSigned
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_ROLE_SIGNED_VERSION)
                .setName(role.getRoleName())
                .setRpk(ByteString.copyFrom(role.getRpk()))
                .build()
                .toByteArray();

        byte[] signature = generateSignature(roleSigned);

        return PurekitProtosV3Storage.Role
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_ROLE_VERSION)
                .setRoleSigned(ByteString.copyFrom(roleSigned))
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    /**
     * Parses and verifies signature of Role
     *
     * @param protobufRecord protobuf
     *
     * @return Role
     *
     * @throws PureStorageException PureStorageException
     */
    public Role parseRole(PurekitProtosV3Storage.Role protobufRecord) throws PureStorageException {
        ValidateUtils.checkNull(protobufRecord, "protobufRecord");

        verifySignature(protobufRecord.getSignature().toByteArray(), protobufRecord.getRoleSigned().toByteArray());

        PurekitProtosV3Storage.RoleSigned roleSigned;
        try {
            roleSigned = PurekitProtosV3Storage.RoleSigned.parseFrom(protobufRecord.getRoleSigned());
        } catch (InvalidProtocolBufferException e) {
            throw new PureStorageInvalidProtobufException(e);
        }

        return new Role(roleSigned.getName(), roleSigned.getRpk().toByteArray());
    }

    /**
     * Signs and serializes RoleAssignment
     *
     * @param roleAssignment RoleAssignment
     *
     * @return protobuf record
     *
     * @throws PureStorageException PureStorageException
     */
    public PurekitProtosV3Storage.RoleAssignment serializeRoleAssignment(RoleAssignment roleAssignment) throws PureStorageException {
        ValidateUtils.checkNull(roleAssignment, "roleAssignment");

        byte[] roleAssignmentSigned = PurekitProtosV3Storage.RoleAssignmentSigned
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_ROLE_ASSIGNMENT_SIGNED_VERSION)
                .setRoleName(roleAssignment.getRoleName())
                .setUserId(roleAssignment.getUserId())
                .setEncryptedRsk(ByteString.copyFrom(roleAssignment.getEncryptedRsk()))
                .setPublicKeyId(ByteString.copyFrom(roleAssignment.getPublicKeyId()))
                .build()
                .toByteArray();

        byte[] signature = generateSignature(roleAssignmentSigned);

        return PurekitProtosV3Storage.RoleAssignment
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_ROLE_ASSIGNMENT_VERSION)
                .setRoleAssignmentSigned(ByteString.copyFrom(roleAssignmentSigned))
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    /**
     * Parses and verifies signature of RoleAssignment
     *
     * @param protobufRecord protobuf
     *
     * @return RoleAssignment
     *
     * @throws PureStorageException PureStorageException
     */
    public RoleAssignment parseRoleAssignment(PurekitProtosV3Storage.RoleAssignment protobufRecord) throws PureStorageException {
        ValidateUtils.checkNull(protobufRecord, "protobufRecord");

        verifySignature(protobufRecord.getSignature().toByteArray(), protobufRecord.getRoleAssignmentSigned().toByteArray());

        PurekitProtosV3Storage.RoleAssignmentSigned roleAssignmentSigned;
        try {
            roleAssignmentSigned = PurekitProtosV3Storage.RoleAssignmentSigned.parseFrom(protobufRecord.getRoleAssignmentSigned());
        } catch (InvalidProtocolBufferException e) {
            throw new PureStorageInvalidProtobufException(e);
        }

        return new RoleAssignment(roleAssignmentSigned.getRoleName(), roleAssignmentSigned.getUserId(),
                roleAssignmentSigned.getPublicKeyId().toByteArray(), roleAssignmentSigned.getEncryptedRsk().toByteArray());
    }

    /**
     * Signs and serializes GrantKey
     *
     * @param grantKey GrantKey
     *
     * @return protobuf record
     *
     * @throws PureStorageException PureStorageException
     */
    public PurekitProtosV3Storage.GrantKey serializeGrantKey(GrantKey grantKey) throws PureStorageException {
        ValidateUtils.checkNull(grantKey, "grantKey");

        byte[] grantKeySigned = PurekitProtosV3Storage.GrantKeySigned
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_GRANT_KEY_SIGNED_VERSION)
                .setUserId(grantKey.getUserId())
                .setKeyId(ByteString.copyFrom(grantKey.getKeyId()))
                .setEncryptedGrantKeyBlob(ByteString.copyFrom(grantKey.getEncryptedGrantKeyBlob()))
                .setCreationDate(grantKey.getCreationDate().getTime() / 1000)
                .setExpirationDate(grantKey.getExpirationDate().getTime() / 1000)
                .build()
                .toByteArray();

        byte[] signature = generateSignature(grantKeySigned);

        return PurekitProtosV3Storage.GrantKey
                .newBuilder()
                .setVersion(PureModelSerializer.CURRENT_GRANT_KEY_VERSION)
                .setGrantKeySigned(ByteString.copyFrom(grantKeySigned))
                .setRecordVersion(grantKey.getRecordVersion())
                .setEncryptedGrantKeyWrap(ByteString.copyFrom(grantKey.getEncryptedGrantKeyWrap()))
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    /**
     * Parses and verifies signature of GrantKey
     *
     * @param protobufRecord protobuf
     *
     * @return GrantKey
     *
     * @throws PureStorageException PureStorageException
     */
    public GrantKey parseGrantKey(PurekitProtosV3Storage.GrantKey protobufRecord) throws PureStorageException {
        ValidateUtils.checkNull(protobufRecord, "protobufRecord");

        verifySignature(protobufRecord.getSignature().toByteArray(), protobufRecord.getGrantKeySigned().toByteArray());

        PurekitProtosV3Storage.GrantKeySigned grantKeySigned;
        try {
            grantKeySigned = PurekitProtosV3Storage.GrantKeySigned.parseFrom(protobufRecord.getGrantKeySigned());
        } catch (InvalidProtocolBufferException e) {
            throw new PureStorageInvalidProtobufException(e);
        }

        return new GrantKey(grantKeySigned.getUserId(),
                grantKeySigned.getKeyId().toByteArray(),
                protobufRecord.getRecordVersion(),
                protobufRecord.getEncryptedGrantKeyWrap().toByteArray(),
                grantKeySigned.getEncryptedGrantKeyBlob().toByteArray(),
                new Date(grantKeySigned.getCreationDate() * 1000),
                new Date(grantKeySigned.getExpirationDate() * 1000));
    }
}
