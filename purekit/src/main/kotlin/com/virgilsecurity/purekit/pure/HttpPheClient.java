package com.virgilsecurity.purekit.pure;

import com.virgilsecurity.purekit.client.HttpClientProtobuf;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;

public class HttpPheClient {
    private String authToken;
    private HttpClientProtobuf client;

    public HttpPheClient(String authToken) {
        this.authToken = authToken;
        this.client = new HttpClientProtobuf("FIXME");
    }

    public PurekitProtos.EnrollmentResponse enrollAccount(PurekitProtos.EnrollmentRequest request) throws ProtocolException, ProtocolHttpException {
        return this.client.firePost(
                request,
                HttpClientProtobuf.AvailableRequests.ENROLL,
                null,
                this.authToken,
                PurekitProtos.EnrollmentResponse.parser()
        );
    }

    public PurekitProtos.VerifyPasswordResponse verifyPassword(PurekitProtos.VerifyPasswordRequest request) throws ProtocolException, ProtocolHttpException {
        return this.client.firePost(
                request,
                HttpClientProtobuf.AvailableRequests.VERIFY_PASSWORD,
                null,
                this.authToken,
                PurekitProtos.VerifyPasswordResponse.parser()
        );
    }
}
