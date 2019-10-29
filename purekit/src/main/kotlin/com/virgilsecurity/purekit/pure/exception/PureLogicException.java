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

package com.virgilsecurity.purekit.pure.exception;

public class PureLogicException extends PureException {

    private final ErrorStatus errorStatus;

    public PureLogicException(ErrorStatus errorStatus) {
        super(errorStatus.getMessage());

        this.errorStatus = errorStatus;
    }

    public ErrorStatus getErrorStatus() {
        return errorStatus;
    }

    public enum ErrorStatus {
        USER_NOT_FOUND_IN_STORAGE(0, "User has not been found in the storage"),
        CELL_KEY_NOT_FOUND_IN_STORAGE(1, "Cell key has not been found in the storage"),
        CELL_KEY_ALREADY_EXISTS_IN_STORAGE(2, "Cell key already exists in the storage"),
        STORAGE_SIGNATURE_VERIFICATION_FAILED(3, "Storage signature verification has been failed"),
        KEYS_VERSION_MISMATCH(4, "Keys version mismatch"),
        UPDATE_TOKEN_VERSION_MISMATCH(5, "Update token version mismatch"),
        AK_INVALID_LENGTH(6, "AK invalid length"),
        CREDENTIALS_PARSING_ERROR(7, "Credentials parsing error"),
        USER_ID_MISMATCH(8, "User Id mismatch"),
        DUPLICATE_USER_ID(9, "Duplicate user Id"),
        INVALID_PASSWORD(10, "Invalid password");

        private final int code;
        private final String message;

        ErrorStatus(int code, String message) {
            this.code = code;
            this.message = message;
        }

        public int getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }
    }
}