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

import com.google.protobuf.MessageLite;
import com.google.protobuf.Parser;
import com.virgilsecurity.purekit.build.VersionVirgilAgent;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;
import com.virgilsecurity.purekit.utils.OsUtils;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Logger;

/**
 * HttpClient class intention is to handle http requests.
 */
public class HttpClient {

    private static final Logger LOGGER = Logger.getLogger(HttpClient.class.getName());

    private static final String AUTHORIZATION_HEADER = "AppToken";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String VIRGIL_AGENT_HEADER = "virgil-agent";

    private final String virgilAgent;
    private final URL serviceBaseUrl;
    private final String token;

    /**
     * Http method
     */
    public enum Method {
        GET,
        POST,
        PUT,
        PATCH,
        DELETE
    }

    /**
     * Creating HttpClient with default virgil-agent header.
     *
     * @param serviceBaseUrl service base url
     * @param token access token
     */
    public HttpClient(URL serviceBaseUrl, String token) {
        this.serviceBaseUrl = serviceBaseUrl;
        this.token = token;
        virgilAgent = "purekit;jvm;" + OsUtils.getOsAgentName() + ";" + VersionVirgilAgent.VERSION;
    }

    /**
     * Executes http request
     *
     * @param path ath appended to base ur
     * @param method http method
     * @param request protobuf request
     *
     * @throws HttpClientException HttpClientException
     */
    public void execute(String path, Method method, MessageLite request) throws HttpClientException {
        execute(path, method, request, null);
    }

    /**
     * Executes http request
     *
     * @param path path appended to base ur
     * @param method http method
     * @param request protobuf request
     * @param parser protobuf parser
     * @param <T> Type of response
     *
     * @return parsed response
     *
     * @throws HttpClientException HttpClientException
     */
    public <T> T execute(String path, Method method, MessageLite request, Parser<T> parser) throws HttpClientException {
        try {
            HttpURLConnection urlConnection = createConnection(path, method, token);
            if (request != null) {
                request.writeTo(urlConnection.getOutputStream());
            }
            if (urlConnection.getResponseCode() >= HttpURLConnection.HTTP_BAD_REQUEST) {
                LOGGER.info("Http error occurred...");
                // Get error code from request
                LOGGER.info("Trying to get error info...");
                try {
                    PurekitProtos.HttpError httpError = PurekitProtos.HttpError.parseFrom(urlConnection.getErrorStream());
                    throw new HttpClientServiceException(httpError);
                } catch (IOException e) {
                    LOGGER.warning("Response error body uses unknown format");
                    throw new HttpClientIOException(e);
                }
            } else {
                if (parser != null) {
                    LOGGER.fine("Trying to extract response body...");
                    return parser.parseFrom(urlConnection.getInputStream());
                } else {
                    return null;
                }
            }
        } catch (IOException e) {
            throw new HttpClientIOException(e);
        }
    }

    private HttpURLConnection createConnection(String path, Method method, String token) throws IOException {
        URL url = this.serviceBaseUrl;
        URL finalUrl = new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getFile() + path, null);

        HttpURLConnection urlConnection = (HttpURLConnection) finalUrl.openConnection();
        urlConnection.setRequestMethod(method.toString());
        urlConnection.setUseCaches(false);

        switch (method) {
            case DELETE:
            case POST:
            case PUT:
            case PATCH:
                urlConnection.setDoOutput(true);
                break;
            case GET:
                break;
        }

        if (token != null && !token.isEmpty()) {
            urlConnection.setRequestProperty(AUTHORIZATION_HEADER, token);
        } else {
            LOGGER.warning("Provided token is blank");
        }

        urlConnection.setRequestProperty(CONTENT_TYPE_HEADER, "application/protobuf");
        urlConnection.setRequestProperty(VIRGIL_AGENT_HEADER, virgilAgent);

        return urlConnection;
    }
}
