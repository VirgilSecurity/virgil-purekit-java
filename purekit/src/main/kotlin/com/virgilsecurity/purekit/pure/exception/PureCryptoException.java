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

import com.virgilsecurity.crypto.foundation.FoundationException;
import com.virgilsecurity.crypto.phe.PheException;

public class PureCryptoException extends PureException {
    private final FoundationException foundationException;
    private final PheException pheException;
    private final PureCryptoException.ErrorStatus errorStatus;

    public PureCryptoException(PureCryptoException.ErrorStatus errorStatus) {
        super(errorStatus.getMessage());

        if (errorStatus == ErrorStatus.UNDERLYING_FOUNDATION_EXCEPTION
                || errorStatus == ErrorStatus.UNDERLYING_PHE_EXCEPTION) {
            throw new RuntimeException();
        }

        this.errorStatus = errorStatus;
        this.foundationException = null;
        this.pheException = null;
    }

    public PureCryptoException(FoundationException foundationException) {
        super(foundationException.getMessage());

        this.errorStatus = ErrorStatus.UNDERLYING_FOUNDATION_EXCEPTION;
        this.foundationException = foundationException;
        this.pheException = null;
    }

    public PureCryptoException(PheException pheException) {
        super(pheException.getMessage());

        this.errorStatus = ErrorStatus.UNDERLYING_PHE_EXCEPTION;
        this.foundationException = null;
        this.pheException = pheException;
    }

    public PureCryptoException.ErrorStatus getErrorStatus() {
        return errorStatus;
    }

    public FoundationException getFoundationException() {
        return foundationException;
    }

    public PheException getPheException() {
        return pheException;
    }

    public enum ErrorStatus {
        UNDERLYING_FOUNDATION_EXCEPTION(1, "Underlying foundation exception"),
        UNDERLYING_PHE_EXCEPTION(2, "Underlying phe exception"),
        SIGNER_IS_ABSENT(3, "Signer is absent"),
        SIGNATURE_IS_ABSENT(4, "Signature is absent"),
        SIGNATURE_VERIFICATION_FAILED(6, "Signature verification failed");

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
