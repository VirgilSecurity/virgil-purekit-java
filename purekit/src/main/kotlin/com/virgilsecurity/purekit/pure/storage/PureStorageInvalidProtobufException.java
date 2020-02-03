package com.virgilsecurity.purekit.pure.storage;

import com.google.protobuf.InvalidProtocolBufferException;

public class PureStorageInvalidProtobufException extends PureStorageException {
    private final InvalidProtocolBufferException invalidProtocolBufferException;

    public PureStorageInvalidProtobufException(InvalidProtocolBufferException invalidProtocolBufferException) {
        super();

        this.invalidProtocolBufferException = invalidProtocolBufferException;
    }

    public InvalidProtocolBufferException getInvalidProtocolBufferException() {
        return invalidProtocolBufferException;
    };
}
