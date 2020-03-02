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

package com.virgilsecurity.purekit.storage.exception;

/**
 * Common PureStorage exceptions
 */
public class PureStorageGenericException extends PureStorageException {
    private final PureStorageGenericException.ErrorStatus errorStatus;

    /**
     * Constructor
     *
     * @param errorStatus errorStatus
     */
    public PureStorageGenericException(PureStorageGenericException.ErrorStatus errorStatus) {
        super(errorStatus.getMessage());

        this.errorStatus = errorStatus;
    }

    /**
     * Error status
     *
     * @return Error status
     */
    public PureStorageGenericException.ErrorStatus getErrorStatus() {
        return errorStatus;
    }

    /**
     * Error status
     */
    public enum ErrorStatus {
        STORAGE_SIGNATURE_VERIFICATION_FAILED(2, "Storage signature verification has been failed"),
        USER_ID_MISMATCH(3, "User Id mismatch"),
        CELL_KEY_ID_MISMATCH(4, "Cell key id mismatch"),
        RECORD_VERSION_MISMATCH(5, "Record version mismatch"),
        ROLE_NAME_MISMATCH(6, "Role name mismatch"),
        ROLE_USER_ID_MISMATCH(7, "Role user id mismatch"),
        ROLE_NAME_USER_ID_MISMATCH(8, "Role name and user id mismatch"),
        USER_COUNT_MISMATCH(9, "User count mismatch"),
        DUPLICATE_ROLE_NAME(10, "Duplicate role name"),
        GRANT_KEY_ID_MISMATCH(12, "Grant key id mismatch"),
        INVALID_PROTOBUF(13, "Invalid protobuf"),
        SIGNING_EXCEPTION(14, "Signing exception"),
        VERIFICATION_EXCEPTION(15, "Verification exception"),
        KEY_ID_MISMATCH(16, "Key id mismatch"),
        USER_ALREADY_EXISTS(19, "User already exists"),
        ROLE_ALREADY_EXISTS(20, "Role already exists"),
        ROLE_ASSIGNMENT_ALREADY_EXISTS(21, "Role assignment already exists"),
        GRANT_KEY_ALREADY_EXISTS(22, "Grant key already exists");

        private final int code;
        private final String message;

        ErrorStatus(int code, String message) {
            this.code = code;
            this.message = message;
        }

        /**
         * Error code
         *
         * @return error code
         */
        public int getCode() {
            return code;
        }

        /**
         * Error message
         *
         * @return error message
         */
        public String getMessage() {
            return message;
        }
    }
}
