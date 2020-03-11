/*
 * Copyright (c) 2015-2020, Virgil Security, Inc.
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

package com.virgilsecurity.purekit.client;

import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.utils.ValidationUtils;

import java.net.URL;

/**
 * HttpPheClient class is for http interactions with PHE service.
 */
public class HttpPheClient {

    private final HttpClient client;

    /**
     * PHE service url
     */
    public static final String SERVICE_ADDRESS = "https://api.virgilsecurity.com/phe/v1";

    /**
     * Instantiates HttpPheClient.
     *
     * @param appToken Application token.
     * @param serviceAddress Service url.
     */
    public HttpPheClient(String appToken, URL serviceAddress) {
        ValidationUtils.checkNullOrEmpty(appToken, "appToken");
        ValidationUtils.checkNull(serviceAddress, "serviceAddress");

        this.client = new HttpClient(serviceAddress, appToken);
    }

    /**
     * Enrolls new account.
     *
     * @param request Enrollment request.
     *
     * @return Enrollment response.
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtos.EnrollmentResponse enrollAccount(PurekitProtos.EnrollmentRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/enroll",
                HttpClient.Method.POST,
                request,
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
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtos.VerifyPasswordResponse verifyPassword(PurekitProtos.VerifyPasswordRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/verify-password",
                HttpClient.Method.POST,
                request,
                PurekitProtos.VerifyPasswordResponse.parser()
        );
    }
}
