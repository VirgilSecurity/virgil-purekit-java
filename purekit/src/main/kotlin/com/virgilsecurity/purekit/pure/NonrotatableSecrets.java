package com.virgilsecurity.purekit.pure;

import com.virgilsecurity.sdk.crypto.VirgilKeyPair;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;

public class NonrotatableSecrets {
    private final byte[] ak;
    private final VirgilKeyPair vskp;
    private final VirgilKeyPair oskp;

    public byte[] getAk() {
        return ak;
    }

    public VirgilKeyPair getVskp() {
        return vskp;
    }

    public VirgilKeyPair getOskp() {
        return oskp;
    }

    public NonrotatableSecrets(byte[] ak, VirgilKeyPair vskp, VirgilKeyPair oskp) {
        this.ak = ak;
        this.vskp = vskp;
        this.oskp = oskp;
    }
}
