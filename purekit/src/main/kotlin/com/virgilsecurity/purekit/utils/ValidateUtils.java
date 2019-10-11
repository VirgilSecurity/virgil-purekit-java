package com.virgilsecurity.purekit.utils;

import java.util.Map;

import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * ValidateUtils class.
 */
public class ValidateUtils {

  /**
   * Throws NullArgumentException if an argument is null and EmptyArgumentException if argument
   * is empty.
   */
  public static void checkNullOrEmpty(Map<String, String> argumentsToCheck) {
    if (argumentsToCheck == null || argumentsToCheck.size() == 0) {
      throw new IllegalStateException("argumentsToCheck cannot be null or empty");
    }

    for (Map.Entry<String, String> argument : argumentsToCheck.entrySet()) {
      if (argument.getKey() == null) {
        throw new NullArgumentException(argument.getValue());
      }
      if (argument.getKey().isEmpty()) {
        throw new EmptyArgumentException(argument.getValue());
      }
    }
  }

  public static void checkNull(Map<Object, String> argumentsToCheck) {
    if (argumentsToCheck == null || argumentsToCheck.size() == 0) {
      throw new IllegalStateException("argumentsToCheck cannot be null or empty");
    }

    for (Map.Entry<Object, String> argument : argumentsToCheck.entrySet()) {
      if (argument.getKey() == null) {
        throw new NullArgumentException(argument.getValue());
      }
    }
  }
}
