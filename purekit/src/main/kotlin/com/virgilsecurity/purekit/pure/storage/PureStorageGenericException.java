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
        USER_NOT_FOUND_IN_STORAGE(1, "User has not been found in the storage"),
        CELL_KEY_ALREADY_EXISTS_IN_STORAGE(2, "Cell key already exists in the storage"),
        STORAGE_SIGNATURE_VERIFICATION_FAILED(3, "Storage signature verification has been failed"),
        USER_ID_MISMATCH(4, "User Id mismatch"),
        CELL_KEY_ID_MISMATCH(5, "Cell key id mismatch"),
        PHE_VERSION_MISMATCH(6, "PHE version mismatch"),
        ROLE_NAME_MISMATCH(7, "Role name mismatch"),
        ROLE_USER_ID_MISMATCH(8, "Role user id mismatch"),
        ROLE_NAME_USER_ID_MISMATCH(9, "Role name and user id mismatch"),
        DUPLICATE_USER_ID(10, "Duplicate user Id"),
        DUPLICATE_ROLE_NAME(11, "Duplicate role name"),
        GRANT_KEY_NOT_FOUND_IN_STORAGE(12, "Grant key has not been found in the storage"),
        GRANT_KEY_ID_MISMATCH(13, "Grant key id mismatch"),
        INVALID_PROTOBUF(14, "Invalid protobuf"),
        SIGNING_EXCEPTION(15, "Signing exception"),
        VERIFICATION_EXCEPTION(16, "Verification exception"),
        KEY_ID_MISMATCH(17, "Key id mismatch");

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
