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

import com.virgilsecurity.common.exception.EmptyArgumentException;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Client;
import com.virgilsecurity.purekit.protobuf.build.PurekitProtosV3Storage;
import com.virgilsecurity.purekit.utils.ValidationUtils;

import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Class for http interactions with Pure service
 */
public class HttpPureClient {

    private final HttpClient client;

    /**
     * Pure service url
     */
    public static final String SERVICE_ADDRESS = "https://api.virgilsecurity.com/pure/v1";

    /**
     * Instantiates HttpPureClient.
     *
     * @param appToken Application token.
     * @param serviceAddress Service url.
     */
    public HttpPureClient(String appToken, URL serviceAddress) {
        ValidationUtils.checkNullOrEmpty(appToken, "appToken");
        ValidationUtils.checkNull(serviceAddress, "serviceAddress");

        this.client = new HttpClient(serviceAddress, appToken);
    }

    /**
     * Inserts new user.
     *
     * @param userRecord User Record.
     *
     * @throws HttpClientException HttpClientException
     */
    public void insertUser(PurekitProtosV3Storage.UserRecord userRecord) throws HttpClientException {

        ValidationUtils.checkNull(userRecord, "userRecord");
        
        client.execute(
                "/user",
                HttpClient.Method.POST,
                userRecord
        );
    }

    /**
     * Updates user.
     *
     * @param userId User Id.
     * @param userRecord UserRecord.
     *
     * @throws HttpClientException HttpClientException
     */
    public void updateUser(String userId, PurekitProtosV3Storage.UserRecord userRecord) throws HttpClientException {

        ValidationUtils.checkNull(userRecord, "userRecord");
        ValidationUtils.checkNullOrEmpty(userId, "userId");

        client.execute(
                String.format("/user/%s", userId),
                HttpClient.Method.PUT,
                userRecord
        );
    }

    /**
     * Obtains user.
     *
     * @param userId User Id.
     *
     * @return UserRecord.
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.UserRecord getUser(String userId) throws HttpClientException {

        ValidationUtils.checkNullOrEmpty(userId, "userId");

        return client.execute(
                String.format("/user/%s", userId),
                HttpClient.Method.GET,
                null,
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
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.UserRecords getUsers(Collection<String> userIds) throws HttpClientException {

        ValidationUtils.checkNull(userIds, "userIds");
        if (userIds.isEmpty()) {
            throw new EmptyArgumentException("userIds");
        }

        PurekitProtosV3Client.GetUserRecords getUserRecords =
            PurekitProtosV3Client.GetUserRecords.newBuilder().addAllUserIds(userIds).build();

        return client.execute(
                "/get-users",
                HttpClient.Method.POST,
                getUserRecords,
                PurekitProtosV3Storage.UserRecords.parser()
        );
    }

    /**
     * Deletes user.
     *
     * @param userId User Ids.
     * @param cascade Deletes all user cell keys if true.
     *
     * @throws HttpClientException HttpClientException
     */
    public void deleteUser(String userId, boolean cascade) throws HttpClientException {

        ValidationUtils.checkNullOrEmpty(userId, "userId");

        client.execute(
                String.format("/user/%s?cascade=%s", userId, cascade),
                HttpClient.Method.DELETE,
                null
        );
    }

    /**
     * Inserts new cell key.
     *
     * @param cellKey CellKey.
     *
     * @throws HttpClientException HttpClientException
     */
    public void insertCellKey(PurekitProtosV3Storage.CellKey cellKey) throws HttpClientException {

        ValidationUtils.checkNull(cellKey, "cellKey");
        
        client.execute(
                "/cell-key",
                HttpClient.Method.POST,
                cellKey
        );
    }

    /**
     * Updates cell key.
     *
     * @param userId User Id.
     * @param dataId Data id.
     * @param cellKey CellKey.
     *
     * @throws HttpClientException HttpClientException
     */
    public void updateCellKey(String userId, String dataId, PurekitProtosV3Storage.CellKey cellKey) throws HttpClientException {

        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(dataId, "dataId");
        ValidationUtils.checkNull(cellKey, "cellKey");

        client.execute(
                String.format("/cell-key/%s/%s", userId, dataId),
                HttpClient.Method.PUT,
                cellKey
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
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.CellKey getCellKey(String userId, String dataId) throws HttpClientException {

        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(dataId, "dataId");

        return client.execute(
                String.format("/cell-key/%s/%s", userId, dataId),
                HttpClient.Method.GET,
                null,
                PurekitProtosV3Storage.CellKey.parser()
        );
    }

    /**
     * Deletes cell key.
     *
     * @param userId User Ids.
     * @param dataId Data Id.
     *
     * @throws HttpClientException HttpClientException
     */
    public void deleteCellKey(String userId, String dataId) throws HttpClientException {

        ValidationUtils.checkNullOrEmpty(userId, "userId");
        ValidationUtils.checkNullOrEmpty(dataId, "dataId");

        client.execute(
                String.format("/cell-key/%s/%s", userId, dataId),
                HttpClient.Method.DELETE,
                null
        );
    }

    /**
     *
     * Inserts role
     *
     * @param role Role
     *
     * @throws HttpClientException HttpClientException
     */
    public void insertRole(PurekitProtosV3Storage.Role role) throws HttpClientException {

        ValidationUtils.checkNull(role, "role");

        client.execute(
                "/roles",
                HttpClient.Method.POST,
                role
        );
    }

    /**
     * Obtains roles
     *
     * @param getRolesRequest Role names
     *
     * @return Roles
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.Roles getRoles(PurekitProtosV3Client.GetRoles getRolesRequest) throws HttpClientException {

        ValidationUtils.checkNull(getRolesRequest, "getRolesRequest");

        return client.execute(
                "/get-roles",
                HttpClient.Method.POST,
                getRolesRequest,
                PurekitProtosV3Storage.Roles.parser()
        );
    }

    /**
     * Inserts roles assignments
     *
     * @param roleAssignments role assignments
     *
     * @throws HttpClientException HttpClientException
     */
    public void insertRoleAssignments(PurekitProtosV3Storage.RoleAssignments roleAssignments) throws HttpClientException {

        ValidationUtils.checkNull(roleAssignments, "roleAssignments");
        if (roleAssignments.getRoleAssignmentsList().isEmpty()) {
            throw new EmptyArgumentException("roleAssignments");
        }

        client.execute(
                "/role-assignments",
                HttpClient.Method.POST,
                roleAssignments
        );
    }

    /**
     * Obtains role assignments
     *
     * @param request request
     *
     * @return Role assignments
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.RoleAssignments getRoleAssignments(PurekitProtosV3Client.GetRoleAssignments request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/get-role-assignments",
                HttpClient.Method.POST,
                request,
                PurekitProtosV3Storage.RoleAssignments.parser()
        );
    }

    /**
     * Obtains role assignmane
     *
     * @param request request
     *
     * @return RoleAssignment
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.RoleAssignment getRoleAssignment(PurekitProtosV3Client.GetRoleAssignment request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/get-role-assignment",
                HttpClient.Method.POST,
                request,
                PurekitProtosV3Storage.RoleAssignment.parser()
        );
    }

    /**
     * Delete role assignments
     *
     * @param request request
     *
     * @throws HttpClientException HttpClientException
     */
    public void deleteRoleAssignments(PurekitProtosV3Client.DeleteRoleAssignments request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        client.execute(
                "/delete-role-assignments",
                HttpClient.Method.POST,
                request
        );
    }

    /**
     * Inserts new grant key
     *
     * @param grantKey grant key
     *
     * @throws HttpClientException HttpClientException
     */
    public void insertGrantKey(PurekitProtosV3Storage.GrantKey grantKey) throws HttpClientException {
        ValidationUtils.checkNull(grantKey, "grantKey");

        client.execute(
                "/grant-key",
                HttpClient.Method.POST,
                grantKey
        );
    }

    /**
     * Obtains grant key
     *
     * @param request request
     *
     * @return grant key
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.GrantKey getGrantKey(PurekitProtosV3Client.GrantKeyDescriptor request) throws HttpClientException {
        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/get-grant-key",
                HttpClient.Method.POST,
                request,
                PurekitProtosV3Storage.GrantKey.parser()
        );
    }

    /**
     * Deletes grant key
     *
     * @param request request
     *
     * @throws HttpClientException HttpClientException
     */
    public void deleteGrantKey(PurekitProtosV3Client.GrantKeyDescriptor request) throws HttpClientException {
        ValidationUtils.checkNull(request, "request");

        client.execute(
                "/delete-grant-key",
                HttpClient.Method.POST,
                request
        );
    }
}
