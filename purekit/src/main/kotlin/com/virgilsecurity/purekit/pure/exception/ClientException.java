package com.virgilsecurity.purekit.pure.exception;

import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.pure.exception.PureException;

public class ClientException extends PureException {
    private final ProtocolException protocolException;
    private final ProtocolHttpException protocolHttpException;

    public ClientException(ProtocolException protocolException) {
        this.protocolException = protocolException;
        this.protocolHttpException = null;
    }

    public ClientException(ProtocolHttpException protocolHttpException) {
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
