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
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
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

    public enum Method {
        GET,
        POST,
        PUT,
        PATCH,
        DELETE
    }

    /**
     * Creating HttpClient with default virgil-agent header.
     */
    public HttpClient(URL serviceBaseUrl, String token) {
        this.serviceBaseUrl = serviceBaseUrl;
        this.token = token;
        // FIXME
        virgilAgent = "purekit;jvm;";
    //    virgilAgent = "purekit;jvm;" + OsUtils.osAgentName + ";" + VersionVirgilAgent.VERSION;
    }

    public void execute(String path, Method method, Map<String, String> headers, MessageLite request) throws HttpClientException {
        execute(path, method, headers, request, null);
    }

    public <T> T execute(String path, Method method, Map<String, String> headers, MessageLite request, Parser<T> parser) throws HttpClientException {
        try {
            HttpURLConnection urlConnection = createConnection(path, method, headers, token);
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

    /**
     * Create and configure http connection.
     *
     * @param url    The URL.
     * @param method The HTTP method.
     * @return The connection.
     * @throws IOException if connection couldn't be created.
     */
    private HttpURLConnection createConnection(String path, Method method, Map<String, String> headers, String token) throws IOException {
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

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                urlConnection.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }

        urlConnection.setRequestProperty(CONTENT_TYPE_HEADER, "application/protobuf");
        urlConnection.setRequestProperty(VIRGIL_AGENT_HEADER, virgilAgent);

        return urlConnection;
    }
}
