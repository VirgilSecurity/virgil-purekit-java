package com.virgilsecurity.purekit.pure.exception;

import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;

public class PheClientException extends ClientException {
    public PheClientException(ProtocolException protocolException) {
        super(protocolException);
    }

    public PheClientException(ProtocolHttpException protocolHttpException) {
        super(protocolHttpException);
    }
}
