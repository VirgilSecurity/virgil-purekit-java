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

import java.util.Collection;
import java.util.LinkedHashMap;

/**
 * Class for http interactions with Pure service
 */
public class HttpPureClient {
    private String appToken;
    private HttpClientProtobuf client;

    /**
     * Constructor
     * @param appToken application token
     * @param serviceAddress service url
     */
    public HttpPureClient(String appToken, String serviceAddress) {
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
     * Inserts new user
     * @param userRecord user Record
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public void insertUser(PurekitProtosV3Storage.UserRecord userRecord) throws ProtocolHttpException, ProtocolException {
        this.client.firePost(
                userRecord,
                HttpClientProtobuf.AvailableRequests.INSERT_USER,
                new LinkedHashMap<>(),
                this.appToken,
                null
        );
    }

    /**
     * Updates user
     * @param userRecord UserRecord
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public void updateUser(PurekitProtosV3Storage.UserRecord userRecord) throws ProtocolHttpException, ProtocolException {
        this.client.firePut(
                userRecord,
                HttpClientProtobuf.AvailableRequests.UPDATE_USER,
                new LinkedHashMap<>(),
                this.appToken,
                null
        );
    }

    /**
     * Obtains user
     * @param userId userId
     * @return UserRecord
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public PurekitProtosV3Storage.UserRecord getUser(String userId) throws ProtocolHttpException, ProtocolException {
        // FIXME: Put userId in get parameters

        return this.client.fireGet(
                HttpClientProtobuf.AvailableRequests.GET_USER,
                new LinkedHashMap<>(),
                this.appToken,
                PurekitProtosV3Storage.UserRecord.parser()
        );
    }

    /**
     * Obtains user
     * @param userIds userIds
     * @return UserRecords
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public PurekitProtosV3Storage.UserRecords getUsers(Collection<String> userIds) throws ProtocolHttpException, ProtocolException {
        // FIXME: Put userIds in get parameters

        return this.client.fireGet(
                HttpClientProtobuf.AvailableRequests.GET_USERS,
                new LinkedHashMap<>(),
                this.appToken,
                PurekitProtosV3Storage.UserRecords.parser()
        );
    }

    /**
     * Deletes user
     * @param userId userIds
     * @param cascade deletes all user cell keys if true
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public void deleteUser(String userId, boolean cascade) throws ProtocolHttpException, ProtocolException {
        // FIXME: Put userId and cascade in parameters

        this.client.fireDelete(
                HttpClientProtobuf.AvailableRequests.DELETE_USER,
                new LinkedHashMap<>(),
                this.appToken,
                null
        );
    }

    /**
     * Inserts new cell key
     * @param cellKey CellKey
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public void insertCellKey(PurekitProtosV3Storage.CellKey cellKey) throws ProtocolHttpException, ProtocolException {
        this.client.firePost(
                cellKey,
                HttpClientProtobuf.AvailableRequests.INSERT_CELL_KEY,
                new LinkedHashMap<>(),
                this.appToken,
                null
        );
    }

    /**
     * Updates cell key
     * @param cellKey CellKey
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public void updateCellKey(PurekitProtosV3Storage.CellKey cellKey) throws ProtocolHttpException, ProtocolException {
        this.client.firePut(
                cellKey,
                HttpClientProtobuf.AvailableRequests.UPDATE_CELL_KEY,
                new LinkedHashMap<>(),
                this.appToken,
                null
        );
    }

    /**
     * Obtains cell key
     * @param userId userId
     * @param dataId dataId
     * @return CellKey
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public PurekitProtosV3Storage.CellKey getCellKey(String userId, String dataId) throws ProtocolHttpException, ProtocolException {
        // FIXME: Put userId and dataId in get parameters

        return this.client.fireGet(
                HttpClientProtobuf.AvailableRequests.GET_CELL_KEY,
                new LinkedHashMap<>(),
                this.appToken,
                PurekitProtosV3Storage.CellKey.parser()
        );
    }

    /**
     * Deletes cell key
     * @param userId userIds
     * @param dataId dataId
     * @throws ProtocolHttpException FIXME
     * @throws ProtocolException FIXME
     */
    public void deleteCellKey(String userId, String dataId) throws ProtocolHttpException, ProtocolException {
        // FIXME: Put userId and dataId in parameters

        this.client.fireDelete(
                HttpClientProtobuf.AvailableRequests.DELETE_CELL_KEY,
                new LinkedHashMap<>(),
                this.appToken,
                null
        );
    }
}
