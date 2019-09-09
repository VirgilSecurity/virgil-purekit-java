package com.virgilsecurity.purekit.pure;

import com.virgilsecurity.purekit.client.HttpClientProtobuf;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;

import java.util.LinkedHashMap;

public class HttpPheClient {
    private String authToken;
    private HttpClientProtobuf client;

    public HttpPheClient(String authToken, String serviceAddress) {
        this.authToken = authToken;
        this.client = new HttpClientProtobuf(serviceAddress);
    }

    public PurekitProtos.EnrollmentResponse enrollAccount(PurekitProtos.EnrollmentRequest request) throws ProtocolException, ProtocolHttpException {
        return this.client.firePost(
                request,
                HttpClientProtobuf.AvailableRequests.ENROLL,
                new LinkedHashMap<String, String>(),
                this.authToken,
                PurekitProtos.EnrollmentResponse.parser()
        );
    }

    public PurekitProtos.VerifyPasswordResponse verifyPassword(PurekitProtos.VerifyPasswordRequest request) throws ProtocolException, ProtocolHttpException {
        return this.client.firePost(
                request,
                HttpClientProtobuf.AvailableRequests.VERIFY_PASSWORD,
                new LinkedHashMap<String, String>(),
                this.authToken,
                PurekitProtos.VerifyPasswordResponse.parser()
        );
    }
}
