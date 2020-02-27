package com.virgilsecurity.purekit.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.*;

import com.virgilsecurity.purekit.pure.NonrotatableSecrets;
import com.virgilsecurity.purekit.pure.NonrotatableSecretsGenerator;
import com.virgilsecurity.purekit.pure.exception.PureException;
import com.virgilsecurity.purekit.utils.ThreadUtils;
import org.junit.jupiter.api.Test;

class NonrotatableSecretsGeneratorTest {
    private static final String nms = "6PvWsrUn/U6ggoabbXCriBk7dtV3NfT+cvqbFGG3DGU=";
    private static final String oskpId = "7QksLSjG56g=";
    private static final String vskpId = "l3RDBZ9U6Cs=";

    @Test
    void generate_secrets__fixed_seed__should_match() throws InterruptedException, PureException {
        ThreadUtils.pause();

        byte[] data = Base64.getDecoder().decode(nms);

        NonrotatableSecrets nonrotatableSecrets = NonrotatableSecretsGenerator.generateSecrets(data);

        assertArrayEquals(Base64.getDecoder().decode(oskpId), nonrotatableSecrets.getOskp().getPublicKey().getIdentifier());
        assertArrayEquals(Base64.getDecoder().decode(vskpId), nonrotatableSecrets.getVskp().getPublicKey().getIdentifier());
    }
}
