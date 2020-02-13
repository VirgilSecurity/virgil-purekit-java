package com.virgilsecurity.purekit.utils;

import com.virgilsecurity.common.exception.EmptyArgumentException;
import com.virgilsecurity.common.exception.NullArgumentException;

/**
 * ValidateUtils class.
 */
public class ValidateUtils {

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
