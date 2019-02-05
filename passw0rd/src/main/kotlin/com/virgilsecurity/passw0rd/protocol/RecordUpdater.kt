/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

package com.virgilsecurity.passw0rd.protocol

import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.virgilsecurity.passw0rd.data.InvalidProtobufTypeException
import com.virgilsecurity.passw0rd.data.ProtocolException
import com.virgilsecurity.passw0rd.protobuf.build.Passw0rdProtos
import com.virgilsecurity.passw0rd.utils.Utils
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.future.asCompletableFuture
import virgil.crypto.phe.PheClient
import virgil.crypto.phe.PheException
import java.util.concurrent.CompletableFuture

/**
 * Created by: Danylo Oliinyk.
 * On 01/22/2018 at Virgil Security.
 */

/**
 * RecordUpdater class is for updating records.
 */
object RecordUpdater {

    /**
     * This function increments record version and updates [oldRecord] with provided [updateToken].
     *
     * @throws IllegalArgumentException
     * @throws PheException
     * @throws InvalidProtobufTypeException
     */
    @JvmStatic
    @Throws(IllegalArgumentException::class, PheException::class, InvalidProtobufTypeException::class)
    fun updateEnrollmentRecord(oldRecord: ByteArray, updateToken: String): CompletableFuture<ByteArray> = GlobalScope.async {
        if (oldRecord.isEmpty()) Utils.shouldNotBeEmpty("oldRecord")
        if (updateToken.isBlank()) Utils.shouldNotBeEmpty("update token")

        val (recordVersion, record) = try {
            Passw0rdProtos.DatabaseRecord.parseFrom(oldRecord).let {
                it.version to it.record.toByteArray()
            }
        } catch (e: InvalidProtocolBufferException) {
            throw InvalidProtobufTypeException()
        }

        val (tokenVersion, tokenContent) = Utils.parseVersionAndContent(
                updateToken,
                Utils.PREFIX_UPDATE_TOKEN,
                Utils.KEY_UPDATE_TOKEN
        )

        if ((recordVersion + 1) == tokenVersion) {
            val newRecord = PheClient().updateEnrollmentRecord(record, tokenContent)

            Passw0rdProtos.DatabaseRecord.newBuilder()
                    .setRecord(ByteString.copyFrom(newRecord))
                    .setVersion(tokenVersion).build()
                    .toByteArray()
        } else {
            throw IllegalArgumentException(
                    "Update Token version must be greater by 1 than current. " +
                            "Token version is $tokenVersion. " +
                            "Current version is $recordVersion."
            )
        }
    }.asCompletableFuture()
}