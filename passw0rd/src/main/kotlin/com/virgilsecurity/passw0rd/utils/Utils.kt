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

package com.virgilsecurity.passw0rd.utils

import java.util.*

/**
 * Created by: Danylo Oliinyk.
 * On 01/02/2019 at Virgil Security.
 */

/**
 * Utils class.
 */
object Utils {

    /**
     * This function intention is just to make code a little bit more elegant/concise.
     *
     * @throws IllegalArgumentException
     */
    @Throws(IllegalArgumentException::class)
    fun shouldNotBeEmpty(argumentName: String): Nothing =
        throw IllegalArgumentException("Parameter $argumentName should not be empty")

    /**
     * This function splits string into 3 parts: Prefix, version and decoded base64 content.
     */
    fun parseVersionAndContent(forParse: String, prefix: String, name: String): Pair<Int, ByteArray> {
        val parsedParts = forParse.split('.')
        if (parsedParts.size != 3)
            throw IllegalArgumentException("Provided \'$name\' has wrong parts count. " +
                                                   "Should be \'3\'. Actual is \'{${parsedParts.size}}\'. ")

        if (parsedParts[0] != prefix)
            throw IllegalArgumentException("Wrong token prefix. Should be \'$prefix\'. " +
                                                   "Actual is \'{$parsedParts[0]}\'.")

        val version: Int
        try {
            version = parsedParts[1].toInt()
            if (version < 1)
                throw IllegalArgumentException("$name version can not be zero or negative number.")
        } catch (e: NumberFormatException) {
            throw IllegalArgumentException("$name version can not be parsed.")
        }

        val content: ByteArray
        try {
            content = Base64.getDecoder().decode(parsedParts[2])
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("$name content can not be parsed.")
        }

        return Pair(version, content)
    }

    const val PREFIX_UPDATE_TOKEN = "UT"
    const val PREFIX_SECRET_KEY = "SK"
    const val PREFIX_PUBLIC_KEY = "PK"

    const val KEY_UPDATE_TOKEN = "Update Token"
    const val KEY_SECRET_KEY = "Secret Key"
    const val KEY_PUBLIC_KEY = "Public Key"
}