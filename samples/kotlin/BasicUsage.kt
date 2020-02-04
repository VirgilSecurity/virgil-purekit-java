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

import com.virgilsecurity.purekit.protocol.RecordUpdater
import kotlinx.coroutines.future.await
import java.util.Base64

object BasicUsage {

    @JvmStatic suspend fun main() {
        // Adding test users for the purpose of this guide.
        val users = mutableListOf<User>()
        users += User("alice123", "80815C001", "036-24-9546")
        users += User("bob321", "411C315N1C3", "041-53-8723")

        // Encapsulated PureKit functionality
        val helper = PureHelper()

        // Previous step: Initialize PureKit

        // Enroll all your user accounts
        for (user in users) {
            print("Enrolling user '${user.username}': ")

            // Ideally, you'll ask for users to create a new password, but
            // for this guide, we'll use existing password in DB
            try {
                val (enrollmentRecord, accountKey) = helper.enrollAccount(user.passwordHash).await()

                // Save record to database
                user.record = Base64.getEncoder().encodeToString(enrollmentRecord)

                // Deprecate existing user password field & save in database
                user.passwordHash = ""

                // Use encryptionKey for protecting user data & save in database
                user.ssn = helper.encrypt(user.ssn.toByteArray(), accountKey)

                print("Success\n\n")
            } catch (e: Throwable) {
                print("Error: $e\n\n")
            }

        }

        // Previous step: enroll accounts

        // Verify password of a user one
        val userOne = users[0]
        var key = ByteArray(0)

        try {
            key = helper.verifyPassword(userOne.record, "80815C001").await()

            // Use key for decrypting user data
            val decryptedSsn = helper.decrypt(userOne.ssn, key)

            print("'${userOne.username}'s SSN: $decryptedSsn\n")
        } catch (e: Throwable) {
            print("Error: $e\n\n")
        }

        // Previous step: verify password

        // Use key for encrypting user data
        val homeAddress = "1600 Pennsylvania Ave NW, Washington, DC 20500, EUA".toByteArray()
        val encryptedAddress = helper.encrypt(homeAddress, key)

        // Use key for decrypting user data
        val decryptedAddress = helper.decrypt(encryptedAddress, key)

        print("'${userOne.username}'s encrypted home address: $encryptedAddress\n")
        print("'${userOne.username}'s home address: $decryptedAddress\n")

        // Previous step: initialize PureKit SDK with Update Token

        // Update user records & save to database
        val updateToken = "UT.2.CiDbvtC+i1NnGon/RDmus2FaNZnHfdE6nOgBCOkb2/gucBIgB0BfXesvdvsaplKVm0hFsjuuVxWr5esI2WxuGqwUKTE="

        for (user in users) {
            val record = Base64.getDecoder().decode(user.record)

            try {
                val newRecord = RecordUpdater.updateEnrollmentRecord(record, updateToken).await()
                user.record = Base64.getEncoder().encodeToString(newRecord)
            } catch (e: Throwable) {
                print("Error: $e\n\n")
            }
        }
    }
}
