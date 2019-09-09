package com.virgilsecurity.purekit.pure;

public class PureCryptoData {
    public PureCryptoData(byte[] cms, byte[] body) {
        this.cms = cms;
        this.body = body;
    }

    public byte[] getCms() {
        return cms;
    }

    public byte[] getBody() {
        return body;
    }

    private byte[] cms;
    private byte[] body;
}
