package com.virgilsecurity.purekit.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.*;

import com.virgilsecurity.purekit.pure.NonrotatableSecrets;
import com.virgilsecurity.purekit.pure.NonrotatableSecretsGenerator;
import com.virgilsecurity.purekit.utils.ThreadUtils;
import org.junit.jupiter.api.Test;

class NonrotatableSecretsGeneratorTest {
    private static final String nms = "6PvWsrUn/U6ggoabbXCriBk7dtV3NfT+cvqbFGG3DGU=";
    private static final String ak = "67s7EAt22cKY+M+OFFG7qBbT0f8J0ZIYlCph8rb8vJo=";
    private static final String oskpId = "45IvIXkOQ7c=";
    private static final String vskpId = "7QksLSjG56g=";

    @Test
    void generate_secrets__fixed_seed__should_match() throws InterruptedException {
        ThreadUtils.pause();

        try {
            byte[] data = Base64.getDecoder().decode(nms);

            NonrotatableSecrets nonrotatableSecrets = NonrotatableSecretsGenerator.generateSecrets(data);

            assertArrayEquals(Base64.getDecoder().decode(ak), nonrotatableSecrets.getAk());
            assertArrayEquals(Base64.getDecoder().decode(oskpId), nonrotatableSecrets.getOskp().getPublicKey().getIdentifier());
            assertArrayEquals(Base64.getDecoder().decode(vskpId), nonrotatableSecrets.getVskp().getPublicKey().getIdentifier());
        } catch (Exception e) {
            fail(e);
        }
    }
}
