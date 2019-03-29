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

import com.virgilsecurity.purekit.data.InvalidPasswordException
import com.virgilsecurity.purekit.data.InvalidProtobufTypeException
import com.virgilsecurity.purekit.data.ProtocolException
import com.virgilsecurity.purekit.protocol.Protocol
import com.virgilsecurity.purekit.protocol.ProtocolContext
import com.virgilsecurity.purekit.utils.EnrollResult
import kotlinx.coroutines.Deferred
import virgil.crypto.phe.PheCipher
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException

/**
 * PureHelper class.
 */
class PureHelper {

    private val protocol: Protocol

    init {
        this.protocol = initProtocol()
    }

    // Initialize PureKit
    private fun initProtocol(): Protocol {
        // Set here your PureKit credentials
        val context = ProtocolContext.create(
                "AT.GxqQu6z8kwIO3HuBYAJN1Wdv9YL5yBGl",
                "PK.1.BBtpQGyPxJRXvA5mpc8HCHUMm9a+Zi88ZuOtU/LWhP+dLH+sSKbnHrTubj7+0+KZyaeeuTP34OfGBlCXLIIJT4I=",
                "SK.1.w3IY3Q/7QMUow/poZFs9KpQ5ElsFUjYEbsjoFso2Oec=",
                ""
        )

        return Protocol(context)
    }

    // Initialize PureKit for records rotation
    private fun initProtocolRotating(): Protocol {
        // Set here your PureKit credentials and update token
        val context = ProtocolContext.create(
                "AT.GxqQu6z8kwIO3HuBYAJN1Wdv9YL5yBGl",
                "PK.1.BBtpQGyPxJRXvA5mpc8HCHUMm9a+Zi88ZuOtU/LWhP+dLH+sSKbnHrTubj7+0+KZyaeeuTP34OfGBlCXLIIJT4I=",
                "SK.1.w3IY3Q/7QMUow/poZFs9KpQ5ElsFUjYEbsjoFso2Oec=",
                "UT.2.CiDbvtC+i1NnGon/RDmus2FaNZnHfdE6nOgBCOkb2/gucBIgB0BfXesvdvsaplKVm0hFsjuuVxWr5esI2WxuGqwUKTE="
        )

        return Protocol(context)
    }

    @Throws(ProtocolException::class)
    fun enrollAccount(password: String): CompletableFuture<EnrollResult> {

        return protocol.enrollAccount(password)
    }

    // Verifies password and returns encryption key for a user
    @Throws(ProtocolException::class,
            InvalidProtobufTypeException::class,
            InvalidPasswordException::class)
    fun verifyPassword(base64record: String,
                       password: String): CompletableFuture<ByteArray> {

        val record = Base64.getDecoder().decode(base64record)
        return protocol.verifyPassword(password, record)
    }

    fun encrypt(data: ByteArray, accountKey: ByteArray): String {
        PheCipher().apply { setupDefaults() }
                .use { cipher ->
                    val encrypted = cipher.encrypt(data, accountKey)
                    return Base64.getEncoder().encodeToString(encrypted)
                }
    }

    fun decrypt(base64: String, accountKey: ByteArray): String {
        PheCipher().apply { setupDefaults() }
                .use { cipher ->
                    val bytes = Base64.getDecoder().decode(base64)
                    val decrypted = cipher.decrypt(bytes, accountKey)
                    return String(decrypted)
                }
    }
}
