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

/**
 * OsUtils class.
 */
object OsUtils {

    /**
     * Get current Operation System (OS).
     *
     * @return the OS Name that is currently running the application.
     */
    @JvmStatic val osAgentName: String
        get() {
            if (isAndroidOs)
                return OsNames.ANDROID_OS_NAME.agentName

            val currentOsName = System.getProperty("os.name").toLowerCase()

            for (osName in OsNames.values()) {
                if (currentOsName.startsWith(osName.naming))
                    return osName.agentName
            }

            return OsNames.UNKNOWN_OS.agentName
        }

    /**
     * Checks whether the current OS is android.
     *
     * @return *true* if current OS is android, *false* otherwise.
     */
    private val isAndroidOs: Boolean
        get() {
            return try {
                Class.forName("android.os.Build")
                true
            } catch (e: ClassNotFoundException) {
                false
            }
        }

    /**
     * Enum with names of OSs to filter the *os.name* system property, and return values
     * for virgil-agent.
     */
    private enum class OsNames {
        ANDROID_OS_NAME("android"),
        LINUX_OS_NAME("linux"),
        WINDOWS_OS_NAME("windows"),
        MACOS_OS_NAME("mac os", "darwin"),
        UNKNOWN_OS("unknown");

        val naming: String
        val agentName: String

        constructor(naming: String) {
            this.naming = naming
            this.agentName = naming
        }

        constructor(naming: String, loggedName: String) {
            this.naming = naming
            this.agentName = loggedName
        }

        override fun toString(): String {
            return naming
        }
    }
}
