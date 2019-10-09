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

import java.util.Collection;
import java.util.HashMap;
import java.util.HashMap;

import com.virgilsecurity.purekit.client.HttpClientProtobuf;
import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * Class for http interactions with Pure service
 */
public class HttpPureClient {

    private final String appToken;
    private final HttpClientProtobuf client;

    public static final String SERVICE_ADDRESS = "https://api.virgilsecurity.com/pure/v1";

    /**
     * Instantiates HttpPureClient.
     *
     * @param appToken Application token.
     * @param serviceAddress Service url.
     */
    public HttpPureClient(String appToken, String serviceAddress) {
        if (appToken == null) {
            throw new NullArgumentException("appToken");
        }
        if (appToken.isEmpty()) {
            throw new EmptyArgumentException("appToken");
        }
        if (serviceAddress == null) {
            throw new NullArgumentException("SERVICE_ADDRESS");
        }
        if (serviceAddress.isEmpty()) {
            throw new EmptyArgumentException("SERVICE_ADDRESS");
        }

        this.appToken = appToken;
        this.client = new HttpClientProtobuf(serviceAddress);
    }

    /**
     * Inserts new user.
     *
     * @param userRecord User Record.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void insertUser(PurekitProtosV3Storage.UserRecord userRecord) 
        throws ProtocolHttpException, ProtocolException {
        
        client.firePost(
                userRecord,
                HttpClientProtobuf.AvailableRequests.INSERT_USER.getType(),
                new HashMap<>(),
                this.appToken
        );
    }

    /**
     * Updates user.
     *
     * @param userId User Id.
     * @param userRecord UserRecord.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void updateUser(String userId, PurekitProtosV3Storage.UserRecord userRecord) 
        throws ProtocolHttpException, ProtocolException {
        
        if (userId == null) {
            throw new NullArgumentException("userId");
        }
        if (userId.isEmpty()) {
            throw new EmptyArgumentException("userId");
        }

        client.firePut(
                userRecord,
                String.format(HttpClientProtobuf.AvailableRequests.UPDATE_USER.getType(), userId),
                new HashMap<>(),
                this.appToken
        );
    }

    /**
     * Obtains user.
     *
     * @param userId User Id.
     *
     * @return UserRecord.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public PurekitProtosV3Storage.UserRecord getUser(String userId) 
        throws ProtocolHttpException, ProtocolException {

        if (userId == null) {
            throw new NullArgumentException("userId");
        }
        if (userId.isEmpty()) {
            throw new EmptyArgumentException("userId");
        }
        
        return client.fireGet(
                String.format(HttpClientProtobuf.AvailableRequests.GET_USER.getType(), userId),
                new HashMap<>(),
                this.appToken,
                PurekitProtosV3Storage.UserRecord.parser()
        );
    }

    /**
     * Obtains user.
     *
     * @param userIds User Ids.
     *
     * @return UserRecords.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public PurekitProtosV3Storage.UserRecords getUsers(Collection<String> userIds) 
        throws ProtocolHttpException, ProtocolException {

        if (userIds == null) {
            throw new NullArgumentException("userIds");
        }
//        if (userIds.isEmpty()) { // FIXME can we pass empty userIds?
//            throw new EmptyArgumentException("userIds");
//        }
        
        PurekitProtosV3Storage.GetUserRecords getUserRecords = 
            PurekitProtosV3Storage.GetUserRecords.newBuilder().addAllUserIds(userIds).build();

        return client.firePost(
                getUserRecords,
                HttpClientProtobuf.AvailableRequests.GET_USERS.getType(),
                new HashMap<>(),
                this.appToken,
                PurekitProtosV3Storage.UserRecords.parser()
        );
    }

    /**
     * Deletes user.
     *
     * @param userId User Ids.
     * @param cascade Deletes all user cell keys if true.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void deleteUser(String userId, boolean cascade) 
        throws ProtocolHttpException, ProtocolException {
        // TODO: parameters ideally should not be added directly to url string

        if (userId == null) {
            throw new NullArgumentException("userId");
        }
        if (userId.isEmpty()) {
            throw new EmptyArgumentException("userId");
        }

        client.fireDelete(
                String.format(HttpClientProtobuf.AvailableRequests.DELETE_USER.getType(), 
                              userId, 
                              String.valueOf(cascade)),
                new HashMap<>(),
                this.appToken
        );
    }

    /**
     * Inserts new cell key.
     *
     * @param cellKey CellKey.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void insertCellKey(PurekitProtosV3Storage.CellKey cellKey) 
        throws ProtocolHttpException, ProtocolException {
        
        client.firePost(
                cellKey,
                HttpClientProtobuf.AvailableRequests.INSERT_CELL_KEY.getType(),
                new HashMap<>(),
                this.appToken
        );
    }

    /**
     * Updates cell key.
     *
     * @param userId User Id.
     * @param dataId Data id.
     * @param cellKey CellKey.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void updateCellKey(String userId, String dataId, PurekitProtosV3Storage.CellKey cellKey) 
        throws ProtocolHttpException, ProtocolException {

        validateUserAndData(userId, dataId);

        client.firePut(
                cellKey,
                String.format(HttpClientProtobuf.AvailableRequests.UPDATE_CELL_KEY.getType(), 
                              userId, 
                              dataId),
                new HashMap<>(),
                this.appToken
        );
    }

    /**
     * Obtains cell key.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @return CellKey.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public PurekitProtosV3Storage.CellKey getCellKey(String userId, String dataId)
        throws ProtocolHttpException, ProtocolException {

        validateUserAndData(userId, dataId);

        return client.fireGet(
                String.format(HttpClientProtobuf.AvailableRequests.GET_CELL_KEY.getType(), userId, dataId),
                new HashMap<>(),
                this.appToken,
                PurekitProtosV3Storage.CellKey.parser()
        );
    }

    /**
     * Deletes cell key.
     *
     * @param userId User Ids.
     * @param dataId Data Id.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    public void deleteCellKey(String userId, String dataId)
        throws ProtocolHttpException, ProtocolException {

        validateUserAndData(userId, dataId);

        client.fireDelete(
                String.format(HttpClientProtobuf.AvailableRequests.DELETE_CELL_KEY.getType(),
                              userId,
                              dataId),
                new HashMap<>(),
                this.appToken
        );
    }

    /**
     * Checks whether userId and dataId is null or empty.
     *
     * @param userId User Ids.
     * @param dataId Data Id.
     */
    private void validateUserAndData(String userId, String dataId) {
        if (userId == null) {
            throw new NullArgumentException("userId");
        }
        if (userId.isEmpty()) {
            throw new EmptyArgumentException("userId");
        }
        if (dataId == null) {
            throw new NullArgumentException("dataId");
        }
        if (dataId.isEmpty()) {
            throw new EmptyArgumentException("dataId");
        }
    }
}
