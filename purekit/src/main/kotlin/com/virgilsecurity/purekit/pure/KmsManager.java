package com.virgilsecurity.purekit.pure;

import com.google.protobuf.ByteString;
import com.virgilsecurity.crypto.foundation.Aes256Gcm;
import com.virgilsecurity.crypto.foundation.AuthEncryptAuthEncryptResult;
import com.virgilsecurity.crypto.phe.UokmsClient;
import com.virgilsecurity.crypto.phe.UokmsClientGenerateDecryptRequestResult;
import com.virgilsecurity.crypto.phe.UokmsClientGenerateEncryptWrapResult;
import com.virgilsecurity.crypto.phe.UokmsWrapRotation;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Client;
import com.virgilsecurity.purekit.pure.model.UserRecord;
import com.virgilsecurity.purekit.utils.ValidateUtils;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;

import java.util.Arrays;

class KmsManager {
    public static final String RECOVER_PWD_ALIAS = "RECOVERY_PASSWORD";

    private final int currentVersion;
    private final VirgilCrypto crypto;
    private final UokmsClient currentClient;
    private final UokmsClient previousClient;
    private final HttpKmsClient httpClient;
    private final UokmsWrapRotation kmsRotation;

    public KmsManager(PureContext context) {
        this.crypto = context.getCrypto();
        this.currentClient = new UokmsClient();
        this.currentClient.setOperationRandom(this.crypto.getRng());
        this.currentClient.setRandom(this.crypto.getRng());
        this.currentClient.setKeys(context.getSecretKey().getPayload2(),
                context.getPublicKey().getPayload2());

        if (context.getUpdateToken() != null) {
            this.currentVersion = context.getPublicKey().getVersion() + 1;
            byte[] updateToken = context.getUpdateToken().getPayload2();
            this.kmsRotation = new UokmsWrapRotation();
            this.kmsRotation.setOperationRandom(this.crypto.getRng());
            this.kmsRotation.setUpdateToken(updateToken);
            this.previousClient = new UokmsClient();
            this.previousClient.setOperationRandom(this.crypto.getRng());
            this.previousClient.setRandom(this.crypto.getRng());
            this.previousClient.setKeys(context.getSecretKey().getPayload2(),
                    context.getPublicKey().getPayload2());
            this.currentClient.rotateKeys(context.getUpdateToken().getPayload2());
        } else {
            this.currentVersion = context.getPublicKey().getVersion();
            this.kmsRotation = null;
            this.previousClient = null;
        }

        this.httpClient = context.getKmsClient();
    }

    private UokmsClient getKmsClient(int kmsVersion) throws NullPointerException {
        if (this.currentVersion == kmsVersion) {
            return this.currentClient;
        } else if (this.currentVersion == kmsVersion + 1) {
            return this.previousClient;
        } else {
            throw new NullPointerException("kmsClient");
        }
    }

    private byte[] deriveSecret(UserRecord userRecord) throws ProtocolHttpException, ProtocolException {
        UokmsClient kmsClient = getKmsClient(userRecord.getPheRecordVersion());

        UokmsClientGenerateDecryptRequestResult uokmsClientGenerateDecryptRequestResult = kmsClient.generateDecryptRequest(userRecord.getPasswordResetWrap());

        PurekitProtosV3Client.DecryptRequest decryptRequest = PurekitProtosV3Client.DecryptRequest.newBuilder()
                .setVersion(userRecord.getPheRecordVersion())
                .setAlias(RECOVER_PWD_ALIAS)
                .setRequest(ByteString.copyFrom(uokmsClientGenerateDecryptRequestResult.getDecryptRequest()))
                .build();

        PurekitProtosV3Client.DecryptResponse decryptResponse = httpClient.decrypt(decryptRequest);

        return kmsClient.processDecryptResponse(userRecord.getPasswordResetWrap(),
                uokmsClientGenerateDecryptRequestResult.getDecryptRequest(),
                decryptResponse.getResponse().toByteArray(),
                uokmsClientGenerateDecryptRequestResult.getDeblindFactor(),
                44 /* FIXME */);
    }

    byte[] performRotation(byte[] wrap) {
        ValidateUtils.checkNull(kmsRotation, "kmsUpdateToken");

        return kmsRotation.updateWrap(wrap);
    }

    static class PwdResetData {
        public PwdResetData(byte[] wrap, byte[] blob) {
            this.wrap = wrap;
            this.blob = blob;
        }

        private final byte[] wrap;

        public byte[] getWrap() {
            return wrap;
        }

        public byte[] getBlob() {
            return blob;
        }

        private final byte[] blob;
    }

    byte[] recoverPwd(UserRecord userRecord) throws ProtocolException, ProtocolHttpException {
        byte[] derivedSecret = deriveSecret(userRecord);

        Aes256Gcm aes256Gcm = new Aes256Gcm();

        aes256Gcm.setKey(Arrays.copyOfRange(derivedSecret, 0, aes256Gcm.getKeyLen()));
        aes256Gcm.setNonce(Arrays.copyOfRange(derivedSecret, aes256Gcm.getKeyLen(), aes256Gcm.getKeyLen() + aes256Gcm.getNonceLen()));

        return aes256Gcm.authDecrypt(userRecord.getPasswordResetBlob(), new byte[0], new byte[0]);
    }

    PwdResetData generatePwdResetData(byte[] passwordHash) {
        Aes256Gcm aes256Gcm = new Aes256Gcm();
        UokmsClientGenerateEncryptWrapResult kmsResult = currentClient.generateEncryptWrap(aes256Gcm.getKeyLen() + aes256Gcm.getNonceLen());

        byte[] derivedSecret = kmsResult.getEncryptionKey();

        aes256Gcm.setKey(Arrays.copyOfRange(derivedSecret, 0, aes256Gcm.getKeyLen()));
        aes256Gcm.setNonce(Arrays.copyOfRange(derivedSecret, aes256Gcm.getKeyLen(), aes256Gcm.getKeyLen() + aes256Gcm.getNonceLen()));

        AuthEncryptAuthEncryptResult authEncryptAuthEncryptResult = aes256Gcm.authEncrypt(passwordHash, new byte[0]);

        byte[] resetPwdBlob = new byte[authEncryptAuthEncryptResult.getOut().length + authEncryptAuthEncryptResult.getTag().length];

        System.arraycopy(authEncryptAuthEncryptResult.getOut(), 0, resetPwdBlob, 0, authEncryptAuthEncryptResult.getOut().length);
        System.arraycopy(authEncryptAuthEncryptResult.getTag(), 0, resetPwdBlob, authEncryptAuthEncryptResult.getOut().length, authEncryptAuthEncryptResult.getTag().length);

        return new PwdResetData(kmsResult.getWrap(), resetPwdBlob);
    }
}
