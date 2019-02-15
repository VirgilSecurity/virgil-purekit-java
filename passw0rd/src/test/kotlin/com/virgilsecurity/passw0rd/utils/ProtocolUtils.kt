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

package com.virgilsecurity.passw0rd.utils

import com.virgilsecurity.passw0rd.client.HttpClientProtobuf
import com.virgilsecurity.passw0rd.protocol.Protocol
import com.virgilsecurity.passw0rd.protocol.ProtocolContext
import org.junit.jupiter.api.Assertions

/**
 * ProtocolUtils class.
 */
object ProtocolUtils {

    /**
     * This function initializes [Protocol] with specified credentials.
     * Or if any of arguments is not specified next values will be used:
     * virgilAppToken -> PropertyManager.virgilAppToken,
     * publicKey -> PropertyManager.virgilPublicKeyNew,
     * secretKey -> PropertyManager.virgilSecretKeyNew,
     * updateToken -> PropertyManager.virgilUpdateTokenNew,
     */
    @JvmOverloads @JvmStatic fun initProtocol(serverAddress: String? = PropertyManager.virgilServerAddress,
                                              appToken: String = PropertyManager.virgilAppToken,
                                              publicKey: String = PropertyManager.virgilPublicKeyNew,
                                              secretKey: String = PropertyManager.virgilSecretKeyNew,
                                              updateToken: String = PropertyManager.virgilUpdateTokenNew): Protocol {

        val context = ProtocolContext.create(
                appToken,
                publicKey,
                secretKey,
                updateToken
        )
        Assertions.assertNotNull(context)

        return if (serverAddress != null)
            Protocol(context, HttpClientProtobuf(serverAddress))
        else
            Protocol(context)
    }
}