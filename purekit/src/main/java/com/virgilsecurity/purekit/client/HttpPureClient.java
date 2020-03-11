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
                "/insert-user",
                HttpClient.Method.POST,
                userRecord
        );
    }

    /**
     * Updates user.
     *
     * @param userRecord UserRecord.
     *
     * @throws HttpClientException HttpClientException
     */
    public void updateUser(PurekitProtosV3Storage.UserRecord userRecord) throws HttpClientException {

        ValidationUtils.checkNull(userRecord, "userRecord");

        client.execute(
                "/update-user",
                HttpClient.Method.POST,
                userRecord
        );
    }

    /**
     * Obtains user.
     *
     * @param request GetUserRequest
     *
     * @return UserRecord.
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.UserRecord getUser(PurekitProtosV3Client.GetUserRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/get-user",
                HttpClient.Method.POST,
                request,
                PurekitProtosV3Storage.UserRecord.parser()
        );
    }

    /**
     * Obtains user.
     *
     * @param request GetUsersRequest
     *
     * @return UserRecords.
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.UserRecords getUsers(PurekitProtosV3Client.GetUsersRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/get-users",
                HttpClient.Method.POST,
                request,
                PurekitProtosV3Storage.UserRecords.parser()
        );
    }

    /**
     * Deletes user.
     *
     * @param request DeleteUserRequest
     *
     * @throws HttpClientException HttpClientException
     */
    public void deleteUser(PurekitProtosV3Client.DeleteUserRequest request, boolean cascade) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        client.execute(
                String.format("/delete-user?cascade=%s", cascade),
                HttpClient.Method.POST,
                request
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
                "/insert-cell-key",
                HttpClient.Method.POST,
                cellKey
        );
    }

    /**
     * Updates cell key.
     *
     * @param cellKey CellKey.
     *
     * @throws HttpClientException HttpClientException
     */
    public void updateCellKey(PurekitProtosV3Storage.CellKey cellKey) throws HttpClientException {

        ValidationUtils.checkNull(cellKey, "cellKey");

        client.execute(
                "/update-cell-key",
                HttpClient.Method.POST,
                cellKey
        );
    }

    /**
     * Obtains cell key.
     *
     * @param request GetCellKey
     *
     * @return CellKey.
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.CellKey getCellKey(PurekitProtosV3Client.GetCellKeyRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/get-cell-key",
                HttpClient.Method.POST,
                request,
                PurekitProtosV3Storage.CellKey.parser()
        );
    }

    /**
     * Deletes cell key.
     *
     * @param request DeleteCellKeyRequest
     *
     * @throws HttpClientException HttpClientException
     */
    public void deleteCellKey(PurekitProtosV3Client.DeleteCellKeyRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        client.execute(
                "/delete-cell-key",
                HttpClient.Method.POST,
                request
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
                "/insert-role",
                HttpClient.Method.POST,
                role
        );
    }

    /**
     * Obtains roles
     *
     * @param request GetRolesRequest
     *
     * @return Roles
     *
     * @throws HttpClientException HttpClientException
     */
    public PurekitProtosV3Storage.Roles getRoles(PurekitProtosV3Client.GetRolesRequest request) throws HttpClientException {

        ValidationUtils.checkNull(request, "request");

        return client.execute(
                "/get-roles",
                HttpClient.Method.POST,
                request,
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
    public PurekitProtosV3Storage.RoleAssignments getRoleAssignments(PurekitProtosV3Client.GetRoleAssignmentsRequest request) throws HttpClientException {

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
    public PurekitProtosV3Storage.RoleAssignment getRoleAssignment(PurekitProtosV3Client.GetRoleAssignmentRequest request) throws HttpClientException {

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
    public void deleteRoleAssignments(PurekitProtosV3Client.DeleteRoleAssignmentsRequest request) throws HttpClientException {

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
                "/insert-grant-key",
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
    public PurekitProtosV3Storage.GrantKey getGrantKey(PurekitProtosV3Client.GetGrantKeyRequest request) throws HttpClientException {
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
    public void deleteGrantKey(PurekitProtosV3Client.DeleteGrantKeyRequest request) throws HttpClientException {
        ValidationUtils.checkNull(request, "request");

        client.execute(
                "/delete-grant-key",
                HttpClient.Method.POST,
                request
        );
    }

    /**
     * Deletes role and all assignments
     *
     * @param request deleteRole request
     * @throws HttpClientException HttpClientException
     */
    public void deleteRole(PurekitProtosV3Client.DeleteRoleRequest request) throws HttpClientException {
        ValidationUtils.checkNull(request, "request");

        client.execute(
                "/delete-role",
                HttpClient.Method.POST,
                request
        );
    }
}
