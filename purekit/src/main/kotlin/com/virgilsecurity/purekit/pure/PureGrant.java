package com.virgilsecurity.purekit.pure;

import java.util.Date;

public class PureGrant {
    public byte[] getPhek() {
        return phek;
    }

    public void setPhek(byte[] phek) {
        this.phek = phek;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(Date creationDate) {
        this.creationDate = creationDate;
    }

    private byte[] phek;
    private String sessionId;
    private Date creationDate;
}
