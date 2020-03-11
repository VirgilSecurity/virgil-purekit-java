package com.virgilsecurity.purekit;

/**
 * Pure session params
 */
public class PureSessionParams {
    private String sessionId;
    private long ttl;

    /**
     * Constructor
     *
     * @param sessionId session id
     * @param ttl time to live in seconds
     */
    public PureSessionParams(String sessionId, long ttl) {
        this.sessionId = sessionId;
        this.ttl = ttl;
    }

    /**
     * Constructor
     *
     * @param ttl time to live in seconds
     */
    public PureSessionParams(long ttl) {
        this(null, ttl);
    }

    /**
     * Constructor
     *
     * @param sessionId session id
     */
    public PureSessionParams(String sessionId) {
        this(sessionId, Pure.DEFAULT_GRANT_TTL);
    }

    /**
     * Constructor
     *
     */
    public PureSessionParams() {
        this(null, Pure.DEFAULT_GRANT_TTL);
    }

    /**
     * Returns session id
     *
     * @return session id
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * Sets session id
     *
     * @param sessionId session id
     */
    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Returns time to live in seconds
     *
     * @return time to live in seconds
     */
    public long getTtl() {
        return ttl;
    }

    /**
     * Sets time to live in seconds
     *
     * @param ttl time to live in seconds
     */
    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
