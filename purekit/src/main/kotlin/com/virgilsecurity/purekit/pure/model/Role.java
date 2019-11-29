package com.virgilsecurity.purekit.pure.model;

public class Role {

    public String getRoleName() {
        return roleName;
    }

    public byte[] getRpk() {
        return rpk;
    }

    private String roleName;
    private byte[] rpk;

    public Role(String roleName, byte[] rpk) {
        this.roleName = roleName;
        this.rpk = rpk;
    }
}
