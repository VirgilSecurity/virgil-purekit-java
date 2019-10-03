package com.virgilsecurity.purekit.pure;

public class PureException extends Exception {
    public enum ErrorCode { // FIXME move to java usual style
        USER_NOT_FOUND_IN_STORAGE,
        CELL_KEY_NOT_FOUND_IN_STORAGE,
        CELL_KEY_ALREADY_EXISTS_IN_STORAGE,
        STORAGE_SIGNATURE_VERIFICATION_FAILED,
        KEYS_VERSION_MISMATCH,
        UPDATE_TOKEN_VERSION_MISMATCH,
        AK_INVALID_LENGTH,
        CREDENTIALS_PARSING_ERROR,
        USER_ID_MISMATCH,
        DUPLICATE_USER_ID,
        INVALID_PASSWORD
    }

    public PureException(ErrorCode errorCode) {
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    private final ErrorCode errorCode;
}
