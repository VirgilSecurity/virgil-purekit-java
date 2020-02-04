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

import com.virgilsecurity.purekit.protocol.RecordUpdater;
import com.virgilsecurity.purekit.utils.EnrollResult;
import java.util.ArrayList;
import java.util.Base64;

class BasicUsage {

  public static void main(String[] args) {
    // Adding test users for the purpose of this guide.
    ArrayList<User> users = new ArrayList<>();
    users.add(new User("alice123", "80815C001", "036-24-9546"));
    users.add(new User("bob321", "411C315N1C3", "041-53-8723"));

    // Encapsulated PureKit functionality
    PureHelper helper = new PureHelper();

    // Previous step: Initialize PureKit

    // Enroll all your user accounts
    for (User user : users) {
      System.out.printf("Enrolling user '%s': ", user.getUsername());

      // Ideally, you'll ask for users to create a new password, but
      // for this guide, we'll use existing password in DB
      try {
        EnrollResult enrollResult = helper.enrollAccount(user.getPasswordHash()).get();

        // Save record to database
        user.setRecord(Base64.getEncoder().encodeToString(enrollResult.getEnrollmentRecord()));

        // Deprecate existing user password field & save in database
        user.setPasswordHash("");

        // Use encryptionKey for protecting user data & save in database
        user.setSsn(helper.encrypt(user.getSsn().getBytes(), enrollResult.getAccountKey()));

        System.out.print("Success\n\n");
      } catch (Throwable e) {
        System.out.printf("Error: %s\n\n", e.toString());
      }
    }

    // Previous step: enroll accounts

    // Verify password of a user one
    User userOne = users.get(0);
    byte[] key = new byte[0];

    try {
      key = helper.verifyPassword(userOne.getRecord(), "80815C001").get();

      // Use key for decrypting user data
      String decryptedSsn = helper.decrypt(userOne.getSsn(), key);

      System.out.printf("'%s's SSN: %s\n", userOne.getUsername(), decryptedSsn);
    } catch (Throwable e) {
      System.out.printf("Error: %s\n\n", e.toString());
    }

    // Previous step: verify password

    // Use key for encrypting user data
    byte[] homeAddress = "1600 Pennsylvania Ave NW, Washington, DC 20500, EUA".getBytes();
    String encryptedAddress = helper.encrypt(homeAddress, key);

    // Use key for decrypting user data
    String decryptedAddress = helper.decrypt(encryptedAddress, key);

    System.out.printf("'%s's encrypted home address: %s\n",
                      userOne.getUsername(),
                      encryptedAddress);
    System.out.printf("'%s's home address: %s\n", userOne.getUsername(), decryptedAddress);

    // Previous step: initialize PureKit SDK with Update Token

    // Update user records & save to database
    String updateToken = "UT.2.CiDbvtC+i1NnGon/RDmus2FaNZnHfdE6nOgBCOkb2/gucBIgB0BfXesvdvsaplKVm0hFsjuuVxWr5esI2WxuGqwUKTE=";

    for (User user : users) {
      byte[] record = Base64.getDecoder().decode(user.getRecord());

      try {
        byte[] newRecord = RecordUpdater.updateEnrollmentRecord(record, updateToken).get();
        user.setRecord(Base64.getEncoder().encodeToString(newRecord));
      } catch (Throwable e) {
        System.out.printf("Error: %s\n\n", e.toString());
      }
    }
  }
}
