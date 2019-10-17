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

import com.virgilsecurity.purekit.data.ProtocolException;
import com.virgilsecurity.purekit.data.ProtocolHttpException;
import com.virgilsecurity.purekit.pure.exception.PureException;
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
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    void insertUser(UserRecord userRecord)
        throws ProtocolException, ProtocolHttpException;

    /**
     * Updates a user in a storage.
     *
     * @param userRecord User record.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    void updateUser(UserRecord userRecord)
        throws ProtocolException, ProtocolHttpException;

    /**
     * Obtains a user record with the given userId from a storage.
     *
     * @param userId User Id.
     *
     * @return UserRecord.
     *
     * @throws PureException If a user has not been found in a storage or user id mismatches the one
     * from a server. Use {@link PureException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    UserRecord selectUser(String userId)
        throws PureException, ProtocolException, ProtocolHttpException;

    /**
     * Obtains a users record with the given userId from a storage.
     *
     * @param userIds User Ids. Should not contain duplicates.
     *
     * @return UserRecords.
     *
     * @throws PureException If user Id duplicate has been found or user id mismatches the one
     * from a server. Use {@link PureException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    Iterable<UserRecord> selectUsers(Collection<String> userIds)
        throws PureException, ProtocolException, ProtocolHttpException;

    /**
     * This method throws UnsupportedOperationException, as in case of using Virgil Cloud storage,
     * rotation happens on Virgil side.
     *
     * @param pheRecordVersion PHE record version.
     *
     * @return always throws NotImplementedException.
     *
     * @throws UnsupportedOperationException always.
     */
    Iterable<UserRecord> selectUsers(int pheRecordVersion) throws UnsupportedOperationException;

    /**
     * Deletes user with the given id.
     *
     * @param userId User Id.
     * @param cascade Deletes all user cell keys if true.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    void deleteUser(String userId, boolean cascade) throws ProtocolException, ProtocolHttpException;

    /**
     * Obtains CellKey for given userId and dataId from a storage.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @return CellKey.
     *
     * @throws PureException If cell key has not been found or if storage signature verification has
     * been failed or user id mismatches the one from a server.
     * Use {@link PureException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    CellKey selectKey(String userId, String dataId)
        throws PureException, ProtocolException, ProtocolHttpException;

    /**
     * Insert CellKey key into a storage.
     *
     * @implSpec this method MUST throw {@link PureException} with
     * {@link PureException.ErrorStatus#CELL_KEY_ALREADY_EXISTS_IN_STORAGE} if key with given
     * userId and dataId already exists.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     * @param cellKey Cell key record.
     *
     * @throws PureException If a cell key already exists in a storage.
     * Use {@link PureException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    void insertKey(String userId, String dataId, CellKey cellKey)
        throws PureException, ProtocolException, ProtocolHttpException;

    /**
     * Updates CellKey.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     * @param cellKey Cell key record.
     *
     * @throws PureException If a cell key already exists in a storage.
     * Use {@link PureException#getErrorStatus()} to know the particular case.
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    void updateKey(String userId, String dataId, CellKey cellKey)
        throws PureException, ProtocolException, ProtocolHttpException;

    /**
     * Deletes cell key with given userId and dataId.
     *
     * @param userId User Id.
     * @param dataId Data Id.
     *
     * @throws ProtocolException Thrown if an error from the PHE service has been parsed
     * successfully.
     * @throws ProtocolHttpException Thrown if an error from the PHE service has NOT been parsed
     * successfully. Represents a regular HTTP exception with code and message.
     */
    void deleteKey(String userId, String dataId) throws ProtocolException, ProtocolHttpException;
}
