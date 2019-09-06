package com.virgilsecurity.purekit.pure;

public class AuthResult {
    public PureGrant getGrant() {
        return grant;
    }

    public String getEncryptedGrant() {
        return encryptedGrant;
    }

    private PureGrant grant;
    private String encryptedGrant;

    public AuthResult(PureGrant grant, String encryptedGrant) {
        this.grant = grant;
        this.encryptedGrant = encryptedGrant;
    }
}
