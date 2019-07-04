# Virgil PureKit SDK Kotlin/Java

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-purekit-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-purekit-kotlin)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/purekit/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/purekit)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<img src="https://cdn.virgilsecurity.com/assets/images/github/logos/pure_grey_logo.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a powerful and revolutionary cryptographic technology that provides stronger and more modern security, that secures users' data and lessens the security risks associated with weak passwords.

Virgil PureKit allows developers interacts with Virgil PHE Service to protect users' passwords and sensitive personal identifiable information (PII data) in a database from offline/online attacks and makes stolen passwords/data useless if your database has been compromised. Neither Virgil nor attackers know anything about users' passwords/data.

This technology can be used within any database or login system that uses a password, so it’s accessible for a company of any industry or size.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of users' passwords
- Passwords & data protection from online attacks
- Passwords & data protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key

## Register Your Account
Before starting practicing with the SDK and usage examples make sure that:
- you have a registered Virgil Account at [Virgil Dashboard](https://dashboard.virgilsecurity.com/)
- you created PURE Application
- and you got your PURE application's credentials such as: `App_Secret_Key`, `Service_Public_Key`, `App_Token`


## Install and Configure SDK
The PureKit Kotlin/Java SDK is provided as a package named `purekit` with group id named `com.virgilsecurity`. You can either use `Gradle` or `Maven` to add it to your project dependencies.


### Install SDK Package
Install PureKit SDK library with the following code:

#### Maven

Add `jcenter` repository:

```
<repositories>
	<repository>
		<id>jcenter</id>
		<name>jCenter</name>
		<url>http://jcenter.bintray.com</url>
	</repository>
</repositories>
```

Add `purekit` dependency:

```
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity</groupId>
        <artifactId>purekit</artifactId>
        <version><latest-version></version>
    </dependency>
</dependencies>
```

#### Gradle

Add `jcenter` repository:

```
repositories {
    jcenter()
}
```

Add `purekit` dependency:

```
implementation "com.virgilsecurity:purekit:<latest-version>"
```

The **\<latest-version>** of the SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/purekit)  or in the header of current readme.

To uninstall Pure, see the [Recover Password Hashes](#recover-password-hashes) section.

### Configure SDK
Here is an example of how to specify your credentials SDK class instance:

`Kotlin`:
```kotlin
// here set your PURE app credentials
fun initPureKit(): Protocol {
    val context = ProtocolContext.create(
        appToken = "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
        servicePublicKey = "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls=",
        clientSecretKey = "SK.1.xxx",
        updateToken = "") // updateToken needs to be empty

    return Protocol(context)
}
```

`Java`:
```java
Protocol initPureKit() {
    ProtocolContext context = ProtocolContext.create(
        "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
        "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls=",
        "SK.1.xxx",
        ""); // updateToken needs to be empty

    return new Protocol(context);
}
```

## Prepare Your Database
PureKit SDK allows you to easily perform all the necessary operations to create, verify and rotate user's `record`.

Pure **record** - a user's password that is protected with our PHE technology. Pure `record` contains a version, client & server random salts and two values obtained during execution of the PHE protocol.

In order to create and work with user's `record` you have to set up your database with an additional column.

The column must have the following parameters:
<table class="params">
<thead>
		<tr>
			<th>Parameters</th>
			<th>Type</th>
			<th>Size (bytes)</th>
			<th>Description</th>
		</tr>
</thead>

<tbody>
<tr>
	<td>record</td>
	<td>bytearray</td>
	<td>210</td>
	<td> A unique record, namely a user's protected Pure record.</td>
</tr>

</tbody>
</table>

### Generate a recovery keypair

This step is __optional__. Use this step if you will need to move away from Pure without having to put your users through registering again.

To be able to move away from Pure without having to put your users through registering again, you need to generate a recovery keypair (public and private key). The public key will be used to encrypt passwords hashes at the enrollment step. You will need to store the encrypted hashes in your database.

To generate a recovery keypair, [install Virgil Crypto Library](https://developer.virgilsecurity.com/docs/how-to/virgil-crypto/install-virgil-crypto) and use the code snippet below. Store the public key in your database and save the private key securely on another external device.

> You won’t be able to restore your recovery private key, so it is crucial not to lose it.

`Kotlin`:
```kotlin
import com.virgilsecurity.crypto.foundation.Base64;

val virgilCrypto = VirgilCrypto()
val recoveryKeyPair = virgilCrypto.generateKeyPair()

val recoveryKey = recoveryKeyPair.privateKey

// Export recovery private key
val exportedRecoveryKey = virgilCrypto.exportPrivateKey(recoveryKey)
val exportedKeyB64 = Base64.encode(exportedRecoveryKey).toString()

// Store privateKey

val publicKey = recoveryKeyPair.publicKey
// Put to your DB
```

`Java`:
```java
import com.virgilsecurity.crypto.foundation.Base64;

VirgilCrypto virgilCrypto = new VirgilCrypto();
VirgilKeyPair recoveryKeyPair = virgilCrypto.generateKeyPair();

VirgilPrivateKey recoveryKey = keyPair.getPrivateKey();
// Export recovery private key
byte[] exportedRecoveryKey = virgilCrypto.exportPrivateKey(recoveryKey);
String exportedKeyB64 = new String(Base64.encode(exportedRecoveryKey));
// Store privateKey

VirgilPublicKey publicKey = keyPair.getPublicKey();
// Put to your DB
```

### Prepare your database for storing encrypted password hashes

Now you need to prepare your database for the future passwords hashes recovery. Create a column in your users table or a separate table for storing encrypted user password hashes.

<table class="params">
<thead>
		<tr>
			<th>Parameters</th>
			<th>Type</th>
			<th>Size (bytes)</th>
			<th>Description</th>
		</tr>
</thead>

<tbody>
<tr>
	<td>encrypted_password_hashes</td>
	<td>bytearray</td>
	<td>512</td>
	<td>User password hash, encrypted with the recovery key.</td>
</tr>
</tbody>
</table>

Further, at the [enrollment step](#enroll-user-record) you'll need to encrypt users' password hashes with the generated recovery public key and save them to the `encrypted_password_hashes` column.


## Usage Examples

> You can find out working sample for the following commands in [this directory](/samples)

### Enroll User Record

Use this flow to create a `PureRecord` in your DB for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in into your system to implement PHE technology. You can go through your database and enroll (create) a user's Pure `Record` at any time.

So, in order to create a Pure `Record` for a new database or available one, go through the following operations:
- Take a user's **password** (or its hash or whatever you use) and pass it into the `EnrollAccount` function in a PureKit on your Server side.
- PureKit will send a request to PureKit service to get enrollment.
- Then, PureKit will create a user's Pure `Record`. You need to store this unique user's Pure `Record` in your database in associated column.
- (optional) Encrypt your user password hashes with the recovery key generated in [Generate a recovery keypair](#generate-a-recovery-keypair) and save them to your database.

`Kotlin`:
```kotlin
import com.virgilsecurity.crypto.foundation.Base64;

// create a new encrypted password record using user password or its hash
fun enrollAccount(password: String, protocol: Protocol) {
    val enrollResult = protocol.enrollAccount(password).get()

    // save Pure record to database
    println("Database record:\n ${String(Base64.encode(enrollResult.enrollmentRecord))}")
    val encryptionKey = enrollResult.accountKey

    // use encryptionKey for protecting user data
    val cipher = PheCipher()
    cipher.setupDefaults()
    val encryptedUserData = cipher.encrypt(data, encryptionKey)

    // (optional) use the generated recovery public key to encrypt a user password hash
    // save encryptedPasswordHash into your database
    val encryptedPasswordHash = virgilCrypto.encrypt(passwordHash.toByteArray(), recoveryPublicKey)
}
```

`Java`:
```java
import com.virgilsecurity.crypto.foundation.Base64;

void enrollAccount(String password, Protocol protocol) throws ProtocolException, ExecutionException, InterruptedException {
    EnrollResult enrollResult = protocol.enrollAccount(password).get();

    //save pure record to database
    System.out.println("Database record:\n" +
        new String(Base64.encode(enrollResult.getEnrollmentRecord())));
    byte[] encryptionKey = enrollResult.getAccountKey();

    //use encryptionKey for protecting user data
    PheCipher cipher = new PheCipher();
    cipher.setupDefaults();
    byte[] encryptedUserData = cipher.encrypt(data, encryptionKey);

    //(optional) use the generated recovery public key to encrypt a user password hash
    //save encryptedPasswordHash into your database
    byte[] encryptedPasswordHash = virgilCrypto.encrypt(passwordHash.getBytes(), recoveryPublicKey);
}
```

When you've created a Pure `record` *(record is enrollResult.enrollmentRecord)* for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User Record

Use this flow when a user already has his or her own Pure `record` in your database. This function allows you to verify user's password with the `record` from your DB every time when the user signs in. You have to pass his or her `record` from your DB into the `verifyPassword` function:

`Kotlin`:
```kotlin
fun verifyPassword(password: String, record: ByteArray, protocol: Protocol) {
    val encryptionKey = try {
        protocol.verifyPassword(password, record)
    } catch (exception: InvalidPasswordException) {
        // Invalid password handling
    }

    //use encryptionKey for decrypting user data
    val cipher = PheCipher()
    cipher.setupDefaults()
    val decrypted = cipher.decrypt(encrypted, encryptionKey)
    ...
}
```

`Java`:
```java
void verifyPassword(String password, byte[] record, Protocol protocol)
        throws InvalidProtobufTypeException, ProtocolException, ExecutionException, InterruptedException {
    byte[] encryptionKey;
    try {
        encryptionKey = protocol.verifyPassword(password, record).get();
    } catch (InvalidPasswordException exception) {
        // Invalid password handling
    }

    //use encryptionKey for decrypting user data
    PheCipher cipher = new PheCipher();
    cipher.setupDefaults();
    byte[] decrypted = cipher.decrypt(encrypted, encryptionKey);
    ...
}
```

### Encrypt user data in your database

Not only user's password is a sensitive data. In this flow we will help you to protect any Personally identifiable information (PII) in your database.

PII is a data that could potentially identify a specific individual, and PII can be sensitive.
Sensitive PII is information which, when disclosed, could result in harm to the individual whose privacy has been breached. Sensitive PII should therefore be encrypted in transit and when data is at rest. Such information includes biometric information, medical information, personally identifiable financial information (PIFI) and unique identifiers such as passport or Social Security numbers.

PHE service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from `enrollAccount` or `verifyPassword` functions. The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) the user's `record`. The `encryptionKey` will be updated after user changes own password.

Here is an example of data encryption/decryption with an `encryptionKey`:

`Kotlin`:
```kotlin
fun main() {
    // encryptionKey (accountKey) is obtained from protocol.enrollAccount() or protocol.verifyPassword() calls

    val data = "Personal data".toByteArray()
    val cipher = PheCipher()
    cipher.setupDefaults()

    val ciphertext = cipher.encrypt(data, encryptionKey)
    val decrypted = cipher.decrypt(ciphertext, encryptionKey)

    //use decrypted data
}
```

`Java`:
```java
void main() {
    // encryptionKey (accountKey) is obtained from protocol.enrollAccount() or protocol.verifyPassword() calls

    byte[] data = "Personal data".getBytes();
    PheCipher cipher = new PheCipher();
    cipher.setupDefaults();

    byte[] ciphertext = cipher.encrypt(data, encryptionKey);
    byte[] decrypted = cipher.decrypt(ciphertext, encryptionKey);

    // use decrypted data
}
```

Encryption is performed using AES256-GCM with key & nonce derived from the user's encryptionKey using HKDF and random 256-bit salt.

Virgil Security has Zero knowledge about a user's `encryptionKey`, because the key is calculated every time when you execute `enrollAccount` or `verifyPassword` functions at your server side.


### Rotate app keys and user record
There can never be enough security, so you should rotate your sensitive data regularly (about once a week). Use this flow to get an `UPDATE_TOKEN` for updating user's `RECORD` in your database and to get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application.

Also, use this flow in case your database has been COMPROMISED!

> This action doesn't require to create an additional table or to do any modification with available one. When a user needs to change his or her own password, use the EnrollAccount function to replace user's old Pure record value in your DB with a newRecord.

There is how it works:

**Step 1.** Get your `UPDATE_TOKEN`

Navigate to [Virgil Dashboard](https://dashboard.virgilsecurity.com/login), open your pure application panel and press "Show update token" button to get the `update_token`.

**Step 2.** Initialize PureKit SDK with the `UPDATE_TOKEN`.
Move to PureKit SDK configuration file and specify your `UPDATE_TOKEN`:

`Kotlin`:
```kotlin
// here set your PURE app credentials
fun initPureKit(): Protocol {
    val context = ProtocolContext.create(
        appToken = "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
        servicePublicKey = "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls=",
        clientSecretKey = "SK.1.00000fLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0=",
        updateToken = "UT.2.00000000+0000000000000000000008UfxXDUU2FGkMvKhIgqjxA+hsAtf17K5j11Cnf07jB6uVEvxMJT0lMGv00000=")

    return Protocol(context)
}
```

`Java`:
```java
// here set your PURE app credentials
Protocol initPureKit() {
    ProtocolContext context = ProtocolContext.create(
        "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
        "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls=",
        "SK.1.00000fLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0=",
        "UT.2.00000000+0000000000000000000008UfxXDUU2FGkMvKhIgqjxA+hsAtf17K5j11Cnf07jB6uVEvxMJT0lMGv00000=");

    return new Protocol(context);
}
```

**Step 3.** Start migration. Use the `RecordUpdater.updateEnrollmentRecord()` SDK function to create a user's `newRecord` (you don't need to ask your users to create a new password). The `RecordUpdater.updateEnrollmentRecord()` function requires the `update_token` and user's `oldRecord` from your DB:

`Kotlin`:
```kotlin
fun main() {
    // Get old record from the database
    val oldRecord = ...

    // Update old record
    val newRecord = try {
        RecordUpdater.updateEnrollmentRecord(oldRecord, "UPDATE_TOKEN")
    } catch (exception: IllegalArgumentException) {
        // Handle already updated state
    }

    // Save new record to the database
    saveNewRecord(newRecord)
}
```

`Java`:
```java
void main() throws InvalidProtobufTypeException, ExecutionException, InterruptedException {
    // Get old record from the database
    byte[] oldRecord = ...

    // Update old record
    byte[] newRecord;
    try {
        newRecord = RecordUpdater.updateEnrollmentRecord(oldRecord, "UPDATE_TOKEN").get();
    } catch (IllegalArgumentException exception) {
        // Handle already updated state
    }

    // Save new record to the database
    saveNewRecord(newRecord);
}
```

So, run the `RecordUpdater.updateEnrollmentRecord()` function and save user's `newRecord` into your database.

Since the SDK is able to work simultaneously with two versions of user's records (`newRecord` and `oldRecord`), this will not affect the backend or users. This means, if a user logs into your system when you do the migration, the PureKit SDK will verify his password without any problems because PHE Service can work with both user's records (`newRecord` and `oldRecord`).

**Step 4.** Get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application

Use Virgil CLI `update-keys` command and your `UPDATE_TOKEN` to update the `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY`:

```bash
// FreeBSD / Linux / Mac OS
./virgil pure update-keys <service_public_key> <app_secret_key> <update_token>

// Windows OS
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

**Step 5.** Move to PureKit SDK configuration and replace your previous `APP_SECRET_KEY`,  `SERVICE_PUBLIC_KEY` with a new one (`APP_TOKEN` will be the same). Delete previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` and `UPDATE_TOKEN`.

`Kotlin`:
```kotlin
// here set your PURE app credentials
fun initPureKitNew(): Protocol {
    val context = ProtocolContext.create(
        appToken = "APP_TOKEN_HERE",
        servicePublicKey = "NEW_SERVICE_PUBLIC_KEY_HERE",
        clientSecretKey = "NEW_APP_SECRET_KEY_HERE",
        updateToken = "") // updateToken needs to be empty

    return Protocol(context)
}
```

`Java`:
```java
Protocol initPureKitNew() {
    ProtocolContext context = ProtocolContext.create(
        "APP_TOKEN_HERE",
        "NEW_SERVICE_PUBLIC_KEY_HERE",
        "NEW_APP_SECRET_KEY_HERE",
        ""); // updateToken needs to be empty

    return new Protocol(context);
}
```

### Recover password hashes

Use this step if you're uninstalling Pure. 

Password hashes recovery is carried out by decrypting the encrypted users password hashes in your database and replacing the Pure records with them.

In order to recover the original password hashes, you need to prepare your recovery private key. If you don't have a recovery key, then you have to ask your users to go through the registration process again to restore their passwords.

Use your recovery private key to get original password hashes:

`Kotlin`:
```kotlin
import com.virgilsecurity.crypto.foundation.Base64;

// Import recovery private key
byte[] exportedKey = Base64.decode(exportedKeyB64.getBytes());
VirgilPrivateKey recoveryPrivateKey = virgilCrypto.importPrivateKey(exportedKey).getPrivateKey();

// decrypt password hashes and save them in database
byte[] decryptedPasswordHash = virgilCrypto.decrypt(encryptedPasswordHash, recoveryPrivateKey);
```

`Java`:
```java
import com.virgilsecurity.crypto.foundation.Base64;

// Import recovery private key
byte[] exportedKey = Base64.decode(exportedKeyB64.getBytes());
VirgilPrivateKey recoveryPrivateKey = virgilCrypto.importPrivateKey(exportedKey).getPrivateKey();

// decrypt password hashes and save them in database
byte[] decryptedPasswordHash = virgilCrypto.decrypt(encryptedPasswordHash, recoveryPrivateKey);
```

Save the decrypted users password hashes into your database. After the recovery process is done, you can delete all the Pure data and the recovery keypair.

## Docs
* [Virgil Dashboard](https://dashboard.virgilsecurity.com)
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send an email to support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
