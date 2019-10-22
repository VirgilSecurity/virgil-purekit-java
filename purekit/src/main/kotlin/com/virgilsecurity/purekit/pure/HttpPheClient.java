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

import java.util.LinkedHashMap;

import com.virgilsecurity.purekit.client.AvailableRequests;
import com.virgilsecurity.purekit.client.HttpClientProtobuf;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.utils.ValidateUtils;

/**
 * HttpPheClient class is for http interactions with PHE service.
 */
public class HttpPheClient {

    private final String appToken;
    private final HttpClientProtobuf client;

    public static final String SERVICE_ADDRESS = "https://api.virgilsecurity.com/phe/v1";

    /**
     * Instantiates HttpPheClient.
     *
     * @param appToken Application token.
     * @param serviceAddress Service url.
     */
    public HttpPheClient(String appToken, String serviceAddress) {
        ValidateUtils.checkNullOrEmpty(appToken, "appToken");
        ValidateUtils.checkNullOrEmpty(serviceAddress, "serviceAddress");

        this.appToken = appToken;
        this.client = new HttpClientProtobuf(serviceAddress);
    }

    /**
     * Enrolls new account.
     *
     * @param request Enrollment request.
     *
     * @return Enrollment response.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
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

    /**
     * Verifies password.
     *
     * @param request Verify password request.
     *
     * @return Verify password response.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
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
