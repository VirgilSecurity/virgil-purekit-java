package com.virgilsecurity.purekit.pure;

import java.util.Date;

// TODO: Add builder?
public class PureGrant {
    private byte[] phek;
    private String userId;
    private String sessionId; // Optional
    private Date creationDate;

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

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
