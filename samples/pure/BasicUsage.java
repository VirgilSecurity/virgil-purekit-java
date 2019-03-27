import com.virgilsecurity.purekit.protocol.*;
import com.virgilsecurity.purekit.utils.*;
import com.virgilsecurity.purekit.data.*;

import virgil.crypto.phe.PheCipher;

import java.util.*;
import java.util.concurrent.ExecutionException;

// For the purpose of this guide, we'll use a simple struct and an array
// to simulate a database. As you go, remove/replace with your actual database logic.
class User {
  String username;

  // If you have any password field for authentication, it can and should
  // be deprecated after enrolling the user with PureKit
  String passwordHash;

  // Data to be protected
  String ssn;

  // Field needed for PureKit
  String record = "";

  User(String username, String passwordHash, String ssn) {
    this.username = username;
    this.passwordHash = passwordHash;
    this.ssn = ssn;
  }
}

class Main {
  static ArrayList<User> userTable = new ArrayList<User>();

  static Protocol initPureKit() {
    // Set here your PureKit credentials
    ProtocolContext context = ProtocolContext.create(
        "AT.GxqQu6z8kwIO3HuBYAJN1Wdv9YL5yBGl",
        "PK.1.BBtpQGyPxJRXvA5mpc8HCHUMm9a+Zi88ZuOtU/LWhP+dLH+sSKbnHrTubj7+0+KZyaeeuTP34OfGBlCXLIIJT4I=",
        "SK.1.w3IY3Q/7QMUow/poZFs9KpQ5ElsFUjYEbsjoFso2Oec=",
        "UT.2.CiDbvtC+i1NnGon/RDmus2FaNZnHfdE6nOgBCOkb2/gucBIgB0BfXesvdvsaplKVm0hFsjuuVxWr5esI2WxuGqwUKTE="
    );

    return new Protocol(context);
  }

  static void enrollAccount(User user, String password, Protocol protocol) throws ProtocolException, ExecutionException, InterruptedException {
    EnrollResult enrollResult = protocol.enrollAccount(password).get();

    byte[] record = enrollResult.getEnrollmentRecord();
    byte[] key = enrollResult.getAccountKey();

    // Save record to database
    user.record = Base64.getEncoder()
                        .encodeToString(record);

    // Deprecate existing user password field & save in database
    user.passwordHash = "";

    // Use encryptionKey for protecting user data & save in database
    PheCipher cipher = new PheCipher();
    cipher.setupDefaults();

    byte[] encryptedSsn = cipher.encrypt(user.ssn.getBytes(), key);
    user.ssn = Base64.getEncoder().encodeToString(encryptedSsn);

    cipher.close();
  }

  // Verifies password and returns encryption key for a user
  static byte[] VerifyPassword(User user, String password, Protocol protocol) throws InvalidProtobufTypeException, ProtocolException, ExecutionException, InterruptedException, InvalidPasswordException {
    byte[] record = Base64.getDecoder().decode(user.record);
    return protocol.verifyPassword(password, record).get();
  }

  public static void main(String[] args) {
    Protocol protocol = initPureKit();
    // Next step: Enroll user accounts

    // Previous step: Initialize PureKit

    // Adding test users for the purpose of this guide.
    userTable.add(new User("alice123", "80815C001", "036-24-9546"));
    userTable.add(new User("bob321", "411C315N1C3", "041-53-8723"));

    // Enroll all your user accounts
    for(User user: userTable) {
      System.out.printf("Enrolling user '%s': ", user.username);

      // Ideally, you'll ask for users to create a new password, but
      // for this guide, we'll use existing password in DB
      try {
        enrollAccount(user, user.passwordHash, protocol);
        System.out.print("Success\n\n");
      } catch(Throwable e) {
        System.out.printf("Error: %s\n\n", e.toString());
      }
    }

    // Previous step: enroll accounts

    // Verify password of a user
    User user = userTable.get(0);
    byte[] key = {};

    try { // try catch for VerifyPassword
      key = VerifyPassword(user, "80815C001", protocol);

      // Use key for decrypting user data
      PheCipher cipher = new PheCipher();
      cipher.setupDefaults();

      byte[] decodedSsn = Base64.getDecoder().decode(user.ssn);
      String decryptedSsn = new String(cipher.decrypt(decodedSsn, key));

      System.out.printf("'%s's SSN: %s\n", user.username, decryptedSsn);
      cipher.close();
    } catch(Throwable e) {
      System.out.printf("Error: %s\n\n", e.toString());
    }

    // Previous step: verify password

    // Use key for encrypting user data
    byte[] homeAddress = "1600 Pennsylvania Ave NW, Washington, DC 20500, EUA".getBytes();

    PheCipher cipher = new PheCipher();
    cipher.setupDefaults();

    byte[] encryptedAddress = cipher.encrypt(homeAddress, key);
    String encryptedAddressB64 = Base64.getEncoder().encodeToString(encryptedAddress);

    // Use key for decrypting user data
    String decryptedAddress = new String(cipher.decrypt(encryptedAddress, key));

    System.out.printf("'%s's encrypted home address: %s\n", user.username, encryptedAddressB64);
    System.out.printf("'%s's home address: %s\n", user.username, decryptedAddress);

    cipher.close();

    // Previous step: initialize PureKit SDK with Update Token

    // Update user records & save to database
    String updateToken = "UT.2.CiDbvtC+i1NnGon/RDmus2FaNZnHfdE6nOgBCOkb2/gucBIgB0BfXesvdvsaplKVm0hFsjuuVxWr5esI2WxuGqwUKTE=";

    for(User u: userTable) {
      byte[] record = Base64.getDecoder().decode(u.record);

      try {
        byte[] newRecord = RecordUpdater.updateEnrollmentRecord(record, updateToken).get();
        u.record = Base64.getEncoder().encodeToString(newRecord);
      } catch(Throwable e) {
        System.out.printf("Error: %s\n\n", e.toString());
      }
    }
  }
}
