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

package com.virgilsecurity.purekit.utils

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File

/**
 * EnvPropertyReader reads properties from JSON file that has format:
 * {
 *   "dev": {
 *     "key1":"value1",
 *     "key2":"value2",
 *   },
 *
 *   "stg": {
 *     // ...
 *   },
 *
 *   "pro": {
 *     // ...
 *   }
 * }
 */
class EnvPropertyReader(environment: Environment = Environment.PRO, filePath: String? = null) {

    private val properties: Map<String, String>

    init {
        val path = filePath ?: PropertyUtils.getSystemProperty(USER_DIR)
        val fileContent = File(path, ENV_FILE_NAME).readText()
        val envJson = JsonParser().parse(fileContent)
        val selectedEnvironment = (envJson as JsonObject).get(environment.type)
        val propertiesSet = (selectedEnvironment as JsonObject).entrySet()

        val propertiesMap = mutableMapOf<String, String>()
        for (entry in propertiesSet) {
            propertiesMap[entry.key] = entry.value.asString
        }

        this.properties = propertiesMap
    }

    fun getProperty(name: String) = properties[name] ?: error("No property with name: \'$name\' provided.")

    companion object {
        private const val USER_DIR = "user.dir"
        private const val ENV_FILE_NAME = "env.json"
    }

    enum class Environment(val type: String) {
        DEV("dev"),
        STG("stg"),
        PRO("pro");

        override fun toString(): String {
            return DEV.type + ", " + STG.type + ", " + PRO.type
        }

        companion object {
            @JvmStatic fun fromType(type: String): Environment {
                return when (type) {
                    DEV.type -> DEV
                    STG.type -> STG
                    PRO.type -> PRO
                    else -> throw IllegalArgumentException("Environment can only be: ${toString()}")
                }
            }
        }
    }
}
