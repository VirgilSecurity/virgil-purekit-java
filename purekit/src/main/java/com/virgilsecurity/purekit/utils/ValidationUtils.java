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

package com.virgilsecurity.purekit.utils;

import com.virgilsecurity.common.exception.EmptyArgumentException;
import com.virgilsecurity.common.exception.NullArgumentException;

/**
 * ValidateUtils class.
 */
public class ValidationUtils {

  /**
   * Throws NullArgumentException if an argument is null and EmptyArgumentException if an argument
   * is empty.
   */
  public static void checkNullOrEmpty(String argument, String name) {
    if (name == null) {
      throw new IllegalStateException("\'name\' cannot be null");
    }


    // Check argument itself
    if (argument == null) {
      throw new NullArgumentException(name);
    }
    if (argument.isEmpty()) {
      throw new EmptyArgumentException(name);
    }
  }

  /**
   * Throws NullArgumentException if an argument is null and EmptyArgumentException if an argument
   * is empty.
   */
  public static void checkNullOrEmpty(byte[] argument, String name) {
    if (name == null) {
      throw new IllegalStateException("\'name\' cannot be null");
    }


    // Check argument itself
    if (argument == null) {
      throw new NullArgumentException(name);
    }
    if (argument.length == 0) {
      throw new EmptyArgumentException(name);
    }
  }

  /**
   * Throws NullArgumentException if an argument is null.
   */
  public static void checkNull(Object argument, String name) {
    if (name == null) {
      throw new IllegalStateException("\'name\' cannot be null");
    }


    // Check argument itself
    if (argument == null) {
      throw new NullArgumentException(name);
    }
  }
}
