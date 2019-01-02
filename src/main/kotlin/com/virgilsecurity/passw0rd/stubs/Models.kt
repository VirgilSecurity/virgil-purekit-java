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

package com.virgilsecurity.passw0rd.stubs

import java.math.BigInteger

/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    12/13/18
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

/**
 * Models class.
 */

data class SecretKey(val bigInteger: BigInteger)

fun SecretKey.encode(): ByteArray = bigInteger.toByteArray()

data class ProofOfFail(
    val term1: ByteArray,
    val term2: ByteArray,
    val term3: ByteArray,
    val term4: ByteArray,
    val blindA: ByteArray,
    val blindB: ByteArray
)

data class ProofOfSuccess(
    val term1: ByteArray,
    val term2: ByteArray,
    val term3: ByteArray,
    val blindX: ByteArray
)

data class FpPoint(val x: BigInteger, val y: BigInteger)

fun FpPoint.getEncoded(): ByteArray = x.toByteArray() + y.toByteArray()

data class PublicKey(val fpPoint: FpPoint)

fun PublicKey.encode(): ByteArray = fpPoint.getEncoded()

data class ProofOfSuccessModel(
    val term1: ByteArray,
    val term2: ByteArray,
    val term3: ByteArray,
    val blindX: ByteArray
)

data class ProofOfFailModel(
    val term1: ByteArray,
    val term2: ByteArray,
    val term3: ByteArray,
    val term4: ByteArray,
    val blindA: ByteArray,
    val blindB: ByteArray
)

data class EnrollmentModel(
    val nonce: ByteArray,
    val c0: ByteArray,
    val c1: ByteArray,
    val proofOfSuccessModel: ProofOfSuccessModel
)

data class EnrollmentRequestModel(val appId: String, val version: Int)
data class EnrollmentResponseModel(val enrollment: EnrollmentModel, val version: Int)

data class VerificationModel(val ns: ByteArray, val c0: ByteArray)
data class VerificationRequestModel(val appId: String, val version: Int, val verification: VerificationModel)
data class VerificationResponseModel(
    val isSuccess: Boolean,
    val c1: ByteArray,
    val proofOfSuccessModel: ProofOfSuccessModel,
    val proofOfFailModel: ProofOfFailModel
)