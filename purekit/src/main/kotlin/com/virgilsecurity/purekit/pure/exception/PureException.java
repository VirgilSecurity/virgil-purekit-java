package com.virgilsecurity.purekit.pure.exception;

public class PureException extends Exception {

    private final ErrorStatus errorStatus;

    public PureException(ErrorStatus errorStatus) {
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
