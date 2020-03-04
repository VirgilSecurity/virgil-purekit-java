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

import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Client;
import com.virgilsecurity.purekit.utils.ValidationUtils;

import java.net.URL;

/**
 * HttpPheClient class is for http interactions with PHE service.
 */
public class HttpKmsClient {

    private final HttpClient client;

    /**
     * KMS service url
     */
    public static final String SERVICE_ADDRESS = "https://api.virgilsecurity.com/kms/v1";

    /**
     * Instantiates HttpKmsClient.
     *
     * @param appToken Application token.
     * @param serviceAddress Service url.
     */
    public HttpKmsClient(String appToken, URL serviceAddress) {
        ValidationUtils.checkNullOrEmpty(appToken, "appToken");
        ValidationUtils.checkNull(serviceAddress, "serviceAddress");

        this.client = new HttpClient(serviceAddress, appToken);
    }

    /**
     * Decrypt query
     *
     * @param request DecryptRequest
     *
     * @return DecryptResponse
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Client.DecryptResponse decrypt(PurekitProtosV3Client.DecryptRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/decrypt",
                HttpClient.Method.POST,
                request,
                PurekitProtosV3Client.DecryptResponse.parser()
        );
    }
}
