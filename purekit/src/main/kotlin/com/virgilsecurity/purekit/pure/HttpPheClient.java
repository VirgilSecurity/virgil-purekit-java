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

import com.virgilsecurity.purekit.client.HttpClientProtobuf;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.protocol.Protocol;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.util.LinkedHashMap;

/**
 * Class for http interactions with PHE service
 */
public class HttpPheClient {
    private final String appToken;
    private final HttpClientProtobuf client;

    /**
     * Service address
     */
    static public String serviceAddress = "https://api.virgilsecurity.com/phe/v1";

    /**
     * Constructor
     * @param appToken application token
     * @param serviceAddress service url
     */
    public HttpPheClient(String appToken, String serviceAddress) {
        if (appToken == null || appToken.isEmpty()) {
            throw new NullPointerException();
        }
        if (serviceAddress == null || serviceAddress.isEmpty()) {
            throw new NullPointerException();
        }

        this.appToken = appToken;
        this.client = new HttpClientProtobuf(serviceAddress);
    }

    /**
     * Enrolls new account
     * @param request enrollment request
     * @return enrollment response
     * @throws ProtocolException FIXME
     * @throws ProtocolHttpException FIXME
     */
    public PurekitProtos.EnrollmentResponse enrollAccount(PurekitProtos.EnrollmentRequest request) throws ProtocolException, ProtocolHttpException {
        return this.client.firePost(
                request,
                HttpClientProtobuf.AvailableRequests.ENROLL.getType(),
                new LinkedHashMap<>(),
                this.appToken,
                PurekitProtos.EnrollmentResponse.parser()
        );
    }

    /**
     * Verifies password
     * @param request verify password request
     * @return verify password response
     * @throws ProtocolException FIXME
     * @throws ProtocolHttpException FIXME
     */
    public PurekitProtos.VerifyPasswordResponse verifyPassword(PurekitProtos.VerifyPasswordRequest request) throws ProtocolException, ProtocolHttpException {
        return this.client.firePost(
                request,
                HttpClientProtobuf.AvailableRequests.VERIFY_PASSWORD.getType(),
                new LinkedHashMap<>(),
                this.appToken,
                PurekitProtos.VerifyPasswordResponse.parser()
        );
    }
}
