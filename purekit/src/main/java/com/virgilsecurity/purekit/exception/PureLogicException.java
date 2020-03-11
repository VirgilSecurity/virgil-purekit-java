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

package com.virgilsecurity.purekit.exception;

/**
 * Pure logic exception
 */
public class PureLogicException extends PureException {

    private final ErrorStatus errorStatus;

    /**
     * Constructor
     *
     * @param errorStatus error status
     */
    public PureLogicException(ErrorStatus errorStatus) {
        super(errorStatus.getMessage());

        this.errorStatus = errorStatus;
    }

    /**
     * Error status
     *
     * @return error status
     */
    public ErrorStatus getErrorStatus() {
        return errorStatus;
    }

    /**
     * Error status
     */
    public enum ErrorStatus {
        KEYS_VERSION_MISMATCH(1, "Keys version mismatch"),
        UPDATE_TOKEN_VERSION_MISMATCH(2, "Update token version mismatch"),
        NONROTABLE_MASTER_SECRET_INVALID_LENGTH(3, "Nonrotatable master secret invalid length"),
        CREDENTIALS_PARSING_ERROR(4, "Credentials parsing error"),
        INVALID_PASSWORD(5, "Invalid password"),
        USER_HAS_NO_ACCESS_TO_DATA(6, "User has no access to data"),
        GRANT_INVALID_PROTOBUF(7, "Grant invalid protobuf"),
        GRANT_IS_EXPIRED(8, "Grant is expired"),
        PASSWORD_RECOVER_REQUEST_THROTTLED(9, "Password recover request was throttled");

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