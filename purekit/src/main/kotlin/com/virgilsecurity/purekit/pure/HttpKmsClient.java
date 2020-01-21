package com.virgilsecurity.purekit.pure;

import com.virgilsecurity.purekit.client.AvailableRequests;
import com.virgilsecurity.purekit.client.HttpClientProtobuf;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.utils.ValidateUtils;

import java.util.LinkedHashMap;

/**
 * HttpPheClient class is for http interactions with PHE service.
 */
public class HttpKmsClient {

    private final String appToken;
    private final HttpClientProtobuf client;

    public static final String SERVICE_ADDRESS = "https://api.virgilsecurity.com/kms/v1";

    /**
     * Instantiates HttpPheClient.
     *
     * @param appToken Application token.
     * @param serviceAddress Service url.
     */
    public HttpKmsClient(String appToken, String serviceAddress) {
        ValidateUtils.checkNullOrEmpty(appToken, "appToken");
        ValidateUtils.checkNullOrEmpty(serviceAddress, "serviceAddress");

        this.appToken = appToken;
        this.client = new HttpClientProtobuf(serviceAddress);
    }

    public PurekitProtos.EnrollmentResponse enrollAccount(PurekitProtos.EnrollmentRequest request)
            throws ProtocolException, ProtocolHttpException {

        return client.firePost(
                request,
                AvailableRequests.ENROLL.getType(),
                new LinkedHashMap<>(),
                this.appToken,
                PurekitProtos.EnrollmentResponse.parser()
        );
    }

    public PurekitProtos.VerifyPasswordResponse verifyPassword(
            PurekitProtos.VerifyPasswordRequest request
    ) throws ProtocolException, ProtocolHttpException {

        return client.firePost(
                request,
                AvailableRequests.VERIFY_PASSWORD.getType(),
                new LinkedHashMap<>(),
                this.appToken,
                PurekitProtos.VerifyPasswordResponse.parser()
        );
    }
}
