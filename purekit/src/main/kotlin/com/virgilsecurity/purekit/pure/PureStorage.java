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

import java.util.Set;

import com.virgilsecurity.purekit.pure.exception.PureLogicException;
import com.virgilsecurity.purekit.pure.model.CellKey;
import com.virgilsecurity.purekit.pure.model.UserRecord;

/**
 * Interface for Pure storage.
 */
public interface PureStorage {

    /**
     * Insert a new user into a storage.
     *
     * @param userRecord User record.
     */
    void insertUser(UserRecord userRecord) throws Exception;

    /**
     * Updates a user in a storage.
     *
     * @param userRecord User record.
     */
    void updateUser(UserRecord userRecord) throws Exception;

    /**
     * Obtains a user record with the given userId from a storage.
     *
     * @param userId User Id.
     *
     * @return UserRecord.
     */
    UserRecord selectUser(String userId) throws Exception;

    /**
     * Obtains users records with given userIds from a storage.
     *
     * @param userIds User Ids.
     *
     * @return UserRecords.
     */
    Iterable<UserRecord> selectUsers(Set<String> userIds) throws Exception;

    /**
     * Obtains users records with given userIds from a storage.
     *
     * @param pheRecordVersion PHE record version.
     *
     * @return UserRecords.
     */
    Iterable<UserRecord> selectUsers(int pheRecordVersion) throws Exception;

    /**
     * Deletes user with the given id.
     *
     * @param userId User Id.
     * @param cascade Deletes all user cell keys if true.
     */
    void deleteUser(String userId, boolean cascade) throws Exception;

    /**
     * Obtains a CellKey for the given userId and dataId from a storage.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @return CellKey.
     */
    CellKey selectKey(String userId, String dataId) throws Exception;

    /**
     * Insert a CellKey key into a storage.
     *
     * @implSpec this method MUST throw {@link PureLogicException} with
     * {@link PureLogicException.ErrorStatus#CELL_KEY_ALREADY_EXISTS_IN_STORAGE} if key with given
     * userId and dataId already exists.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     * @param cellKey Cell key record.
     */
    void insertKey(String userId, String dataId, CellKey cellKey) throws Exception;

    /**
     * Updates a CellKey.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     * @param cellKey Cell key record.
     */
    void updateKey(String userId, String dataId, CellKey cellKey) throws Exception;

    /**
     * Deletes a CellKey with the given userId and dataId.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     */
    void deleteKey(String userId, String dataId) throws Exception;
}
