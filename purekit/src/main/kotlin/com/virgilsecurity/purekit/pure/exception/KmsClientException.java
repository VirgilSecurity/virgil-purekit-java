package com.virgilsecurity.purekit.pure.exception;

import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;

public class KmsClientException extends ClientException {
    public KmsClientException(ProtocolException protocolException) {
        super(protocolException);
    }

    public KmsClientException(ProtocolHttpException protocolHttpException) {
        super(protocolHttpException);
    }
}
