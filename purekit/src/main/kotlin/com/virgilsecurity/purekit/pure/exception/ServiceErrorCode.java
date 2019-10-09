package com.virgilsecurity.purekit.pure.exception;

/**
 * PHE service error codes.
 */
public enum ServiceErrorCode {
    USER_NOT_FOUND(50003),
    CELL_KEY_NOT_FOUND(50004),
    CELL_KEY_ALREADY_EXISTS(50006); // FIXME do we need error code 0 ?

    private final int code;

    ServiceErrorCode(int code) {
        this.code = code;
    }

    /**
     * Error code number.
     *
     * @return Error code number.
     */
    public int getCode() {
        return code;
    }
}
