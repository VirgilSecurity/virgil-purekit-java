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

package com.virgilsecurity.purekit.data

/**
 * Exceptions class.
 */

/**
 * Exception that is thrown when purekit service answers with some error.
 */
class ProtocolException @JvmOverloads constructor(
    val errorCode: Int = -1,
    message: String? = "Unknown error"
) : Exception(message)

/**
 * Exception that is thrown when purekit service answers with some error but not with default protobuf type.
 */
class ProtocolHttpException @JvmOverloads constructor(
    val errorCode: Int = -1,
    message: String? = "Unknown error"
) : Exception(message)

/**
 * Exception that is been thrown when wrong password is used to perform some action.
 */
class InvalidPasswordException(message: String?) : Exception(message)

/**
 * Exception that is been thrown when trying to parse Protobuf message with wrong type.
 */
class InvalidProtobufTypeException(message: String? = "Can not parse model you have given.") : Exception(message)

/**
 * Exception that is been thrown when no keys was found.
 */
//TODO default message is wrong
class NoKeysFoundException(message: String? = "Can not parse model you have given.") : Exception(message)

/**
 * Exception that is been thrown when the proof is wrong.
 */
//TODO default message is wrong
class InvalidProofException(message: String? = "Can not parse model you have given.") : Exception(message)