package com.virgilsecurity.purekit.pure;

import java.util.Date;

// TODO: Add builder?
public class PureGrant {
    private byte[] phesk;
    private String userId;
    private String sessionId; // Optional
    private Date creationDate;

    public byte[] getPhesk() {
        return phesk;
    }

    public void setPhesk(byte[] phesk) {
        this.phesk = phesk;
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
