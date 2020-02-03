package com.virgilsecurity.purekit.pure.storage;

import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;

public class VirgilCloudStorageException extends PureStorageException {
    private final ProtocolException protocolException;
    private final ProtocolHttpException protocolHttpException;

    public VirgilCloudStorageException(ProtocolException protocolException) {
        this.protocolException = protocolException;
        this.protocolHttpException = null;
    }

    public VirgilCloudStorageException(ProtocolHttpException protocolHttpException) {
        this.protocolException = null;
        this.protocolHttpException = protocolHttpException;
    }

    public ProtocolException getProtocolException() {
        return protocolException;
    }

    public ProtocolHttpException getProtocolHttpException() {
        return protocolHttpException;
    }
}
