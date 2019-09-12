/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.purekit.pure;

import com.virgilsecurity.sdk.crypto.VirgilKeyPair;

import java.util.Date;

/**
 *
 */
public class PureGrant {
    private VirgilKeyPair ukp;
    private String userId;
    private String sessionId;
    private Date creationDate;

    /**
     * Constructor
     * @param ukp user key pair
     * @param userId userId
     * @param sessionId sessionId (optional)
     * @param creationDate creation date
     */
    public PureGrant(VirgilKeyPair ukp,
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

    /**
     * Returns user key pair
     * @return User key pair
     */
    public VirgilKeyPair getUkp() {
        return ukp;
    }

    /**
     * Returns session id
     * @return Session id
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Returns creation date
     * @return Creation date
     */
    public Date getCreationDate() {
        return creationDate;
    }

    /**
     * Returns user id
     * @return User id
     */
    public String getUserId() {
        return userId;
    }
}
