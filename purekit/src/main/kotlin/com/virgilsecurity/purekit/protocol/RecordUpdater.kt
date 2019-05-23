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

package com.virgilsecurity.purekit.protocol

import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.virgilsecurity.crypto.phe.PheClient
import com.virgilsecurity.crypto.phe.PheException
import com.virgilsecurity.purekit.data.InvalidProtobufTypeException
import com.virgilsecurity.purekit.protobuf.build.PurekitProtos
import com.virgilsecurity.purekit.utils.KEY_UPDATE_TOKEN
import com.virgilsecurity.purekit.utils.PREFIX_UPDATE_TOKEN
import com.virgilsecurity.purekit.utils.parseVersionAndContent
import com.virgilsecurity.purekit.utils.requires
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.future.asCompletableFuture
import java.util.concurrent.CompletableFuture

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
        requires(oldRecord.isNotEmpty(), "oldRecord")
        requires(updateToken.isNotBlank(), "update token")

        val (recordVersion, record) = try {
            with(PurekitProtos.DatabaseRecord.parseFrom(oldRecord)) {
                version to record.toByteArray()
            }
        } catch (e: InvalidProtocolBufferException) {
            throw InvalidProtobufTypeException()
        }

        val (tokenVersion, tokenContent) = updateToken.parseVersionAndContent(
                PREFIX_UPDATE_TOKEN,
                KEY_UPDATE_TOKEN
        )

        require(recordVersion + 1 == tokenVersion) {
            "Update Token version must be greater by 1 than current. " +
                    "Token version is $tokenVersion. " +
                    "Current version is $recordVersion."
        }

        val newRecord = PheClient().updateEnrollmentRecord(record, tokenContent)
        PurekitProtos.DatabaseRecord.newBuilder()
                .setRecord(ByteString.copyFrom(newRecord))
                .setVersion(tokenVersion).build()
                .toByteArray()
    }.asCompletableFuture()
}