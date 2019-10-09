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

// FIXME: Add typed exceptions?

import java.util.Collection;

import com.virgilsecurity.purekit.pure.model.CellKey;
import com.virgilsecurity.purekit.pure.model.UserRecord;

/**
 * Interface for Pure storage
 */
public interface PureStorage {
    /**
     * Insert new user into storage
     * @param userRecord User record
     * @throws Exception FIXME
     */
    void insertUser(UserRecord userRecord) throws Exception;

    /**
     * Updates user in storage
     * @param userRecord User record
     * @throws Exception FIXME
     */
    void updateUser(UserRecord userRecord) throws Exception;

    /**
     * Obtains user record with given userId from storage
     * @param userId userId
     * @return UserRecord
     * @throws Exception FIXME
     */
    UserRecord selectUser(String userId) throws Exception;

    /**
     * Obtains users record with given userId from storage
     * @param userIds userIds
     * @return UserRecords
     * @throws Exception FIXME
     */
    Iterable<UserRecord> selectUsers(Collection<String> userIds) throws Exception;

    /**
     * Obtains users with given pheRecordVersion from storage
     * @implNote this method should have limit on number of returned values (e.g. 50, 100).
     * Calling method will request records until empty value is returned
     * @param pheRecordVersion PheRecordVersion
     * @return UserRecords
     * @throws Exception FIXME
     */
    Iterable<UserRecord> selectUsers(int pheRecordVersion) throws Exception;

    /**
     * Deletes user with given id
     * @param userId userId
     * @param cascade deletes all user cell keys if true
     * @throws Exception FIXME
     */
    void deleteUser(String userId, boolean cascade) throws Exception;

    /**
     * Obtains CellKey for given userId and dataId from storage
     * @param userId userId
     * @param dataId dataId
     * @return CellKey
     * @throws Exception FIXME
     */
    CellKey selectKey(String userId, String dataId) throws Exception;

    /**
     * Insert CellKey key into storage
     * @implSpec this method MUST throw PureException(CELL_KEY_ALREADY_EXISTS) if key with given userId and dataId already exists
     * @param userId userId
     * @param dataId dataId
     * @param cellKey cell key record
     * @throws Exception FIXME
     */
    void insertKey(String userId, String dataId, CellKey cellKey) throws Exception;

    /**
     * Updates CellKey
     * @param userId userId
     * @param dataId dataId
     * @param cellKey cell key record
     * @throws Exception FIXME
     */
    void updateKey(String userId, String dataId, CellKey cellKey) throws Exception;

    /**
     * Deletes cell key with given userId and dataId
     * @param userId userId
     * @param dataId dataId
     * @throws Exception FIXME
     */
    void deleteKey(String userId, String dataId) throws Exception;
}
