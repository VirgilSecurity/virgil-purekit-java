package com.virgilsecurity.purekit.pure;

import com.virgilsecurity.sdk.crypto.VirgilKeyPair;

import java.util.Date;

// TODO: Add builder?
public class PureGrant {
    private VirgilKeyPair ukp;
    private String userId;
    private String sessionId; // Optional
    private Date creationDate;

    PureGrant(VirgilKeyPair ukp,
                     String userId,
                     String sessionId,
                     Date creationDate) {
        if (ukp == null || userId == null || creationDate == null) {
            throw new NullPointerException();
        }

        this.ukp = ukp;
        this.userId = userId;
        this.sessionId = sessionId;
        this.creationDate = creationDate;
    }

    public VirgilKeyPair getUkp() {
        return ukp;
    }

    public String getSessionId() {
        return sessionId;
    }

    public Date getCreationDate() {
        return creationDate;
    }

    public String getUserId() {
        return userId;
    }
}
