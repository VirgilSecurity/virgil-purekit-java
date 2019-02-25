# Passw0rd SDK Kotlin/Java

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-passw0rd-kotlin.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-passw0rd-kotlin)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/passw0rd/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.virgilsecurity/passw0rd)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<a href="https://passw0rd.io/"><img width="260px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/passw0rd.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) that provides developers with a technology to protect users passwords from offline/online attacks and make stolen passwords useless even if your database has been compromised.

PHE is a new, more secure mechanism that protects user passwords and lessens the security risks associated with weak passwords. Neither Virgil nor attackers know anything about user's password.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of user password
- Protection from online attacks
- Protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key


## Register Your Account
Before starting practicing with the SDK and usage examples make sure that:
- you have a registered at [Virgil Dashboard](https://dashboard.virgilsecurity.com/)
- you created an application for the Passw0rd use case
- and you got your passw0rd application's credentials such as: `App Secret Key`, `Service Public Key`, `App Token`


## Install and Configure SDK
The passw0rd Kotlin/Java SDK is provided as a package named `passw0rd` with group id named `com.virgilsecurity`. You can either use `Gradle` or `Maven` to add it to your project dependencies.


### Install SDK Package
Install passw0rd SDK library with the following code:

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

Add `passw0rd` dependency:

```
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity</groupId>
        <artifactId>passw0rd</artifactId>
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

Add `passw0rd` dependency:

```
implementation "com.virgilsecurity:passw0rd:<latest-version>"
```

The **\<latest-version>** of the SDK can be found in the [Maven Central Repository](https://mvnrepository.com/artifact/com.virgilsecurity/passw0rd)  or in the header of current readme.

### Configure SDK
Here is an example of how to specify your credentials SDK class instance:

`Kotlin`:
```kotlin
// here set your passw0rd credentials
fun initPassw0rd(): Protocol {
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
Protocol initPassw0rd() {
    ProtocolContext context = ProtocolContext.create(
            "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps",
            "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls=",
            "SK.1.xxx",
            ""); // updateToken needs to be empty

    return new Protocol(context);
}
```

## Prepare Your Database
Passw0rd SDK allows you to easily perform all the necessary operations to create, verify and rotate user's `record`.

**Passw0rd record** - a user's password that is protected with our Passw0rd technology. Passw0rd `record` contains a version, client & server random salts and two values obtained during execution of the PHE protocol.

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
	<td>passw0rd_record</td>
	<td>bytearray</td>
	<td>210</td>
	<td> A unique record, namely a user's protected passw0rd.</td>
</tr>

</tbody>
</table>


## Usage Examples

### Enroll User Record

Use this flow to create a new passw0rd's `record` in your DB for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in into your system to implement Passw0rd technology. You can go through your database and enroll (create) a user's `record` at any time.

So, in order to create a `record` for a new database or available one, go through the following operations:
- Take a user's **password** (or its hash or whatever you use) and pass it into the `enrollAccount` function in a SDK on your Server side.
- Passw0rd SDK will send a request to Passw0rd Service to get enrollment.
- Then, Passw0rd SDK will create a user's `record`. You need to store this unique user's `record` in your database in associated column.

`Kotlin`:
```kotlin
// create a new encrypted password record using user password or its hash
fun enrollAccount(password: String, protocol: Protocol) {
    val enrollResult = protocol.enrollAccount(password).get()

    //save record to database
    println("Database record:\n" + Base64.getEncoder().encodeToString(enrollResult.enrollmentRecord))
    val encryptionKey = enrollResult.accountKey
    //use accountKey for protecting user data
    val cipher = PheCipher()
    cipher.setupDefaults()
    val encrypted = cipher.encrypt(data, encryptionKey)
}
```

`Java`:
```java
void enrollAccount(String password,
                   Protocol protocol) throws ProtocolException, ExecutionException, InterruptedException {
    EnrollResult enrollResult = protocol.enrollAccount(password).get();

    //save record to database
    System.out.println("Database record:\n" + Base64.getEncoder()
                                                    .encodeToString(enrollResult.getEnrollmentRecord()));
    byte[] encryptionKey = enrollResult.getAccountKey();
    //use accountKey for protecting user data
    PheCipher cipher = new PheCipher();
    cipher.setupDefaults();
    byte[] encrypted = cipher.encrypt(data, encryptionKey);
}
```

When you've created a passw0rd's `record` *(record is enrollResult.enrollmentRecord)* for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User Record

Use this flow when a user already has his or her own passw0rd's `record` in your database. This function allows you to verify user's password with the `record` from your DB every time when the user signs in. You have to pass his or her `record` from your DB into the `verifyPassword` function:

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
void verifyPassword(String password,
                    byte[] record,
                    Protocol protocol) 
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

## Encrypt user data in your database

Not only user's password is a sensitive data. In this flow we will help you to protect any Personally identifiable information (PII) in your database.

PII is a data that could potentially identify a specific individual, and PII can be sensitive.
Sensitive PII is information which, when disclosed, could result in harm to the individual whose privacy has been breached. Sensitive PII should therefore be encrypted in transit and when data is at rest. Such information includes biometric information, medical information, personally identifiable financial information (PIFI) and unique identifiers such as passport or Social Security numbers.

Passw0rd service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from `enrollAccount` or `verifyPassword` functions. The `encryptionKey` will be the same for both functions.

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


## Rotate app keys and user record
There can never be enough security, so you should rotate your sensitive data regularly (about once a week). Use this flow to get an `UPDATE_TOKEN` for updating user's passw0rd `RECORD` in your database and to get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application.

Also, use this flow in case your database has been COMPROMISED!

> This action doesn't require to create an additional table or to do any modification with available one. When a user needs to change his or her own password, use the EnrollAccount function to replace user's oldPassw0rd record value in your DB with a newRecord.

There is how it works:

**Step 1.** Get your `UPDATE_TOKEN` using [Virgil Dashboard](https://dashboard.virgilsecurity.com)

Move to your Application panel and press “Show update token” button to get the `update_token`.

**Step 2.** Initialize passw0rd SDK with the `UPDATE_TOKEN`.
Move to passw0rd SDK configuration file and specify your `UPDATE_TOKEN`:

`Kotlin`:
```kotlin
// here set your passw0rd credentials
fun initPassw0rd(): Protocol {
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
// here set your passw0rd credentials
Protocol initPassw0rd() {
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

Since the SDK is able to work simultaneously with two versions of user's records (`newRecord` and `oldRecord`), this will not affect the backend or users. This means, if a user logs into your system when you do the migration, the passw0rd SDK will verify his password without any problems because Passw0rd Service can work with both user's records (`newRecord` and `oldRecord`).

**Step 4.** Get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application

Use Virgil CLI `update-keys` command and your `UPDATE_TOKEN` to update the `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY`:

```bash
// FreeBSD / Linux / Mac OS
./virgil passw0rd update-keys <service_public_key> <app_secret_key> <update_token>

// Windows OS
virgil passw0rd update-keys <service_public_key> <app_secret_key> <update_token>
```

**Step 5.** Move to passw0rd SDK configuration and replace your previous `APP_SECRET_KEY`,  `SERVICE_PUBLIC_KEY` with a new one (`APP_TOKEN` will be the same). Delete previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` and `UPDATE_TOKEN`.

`Kotlin`:
```kotlin
// here set your passw0rd credentials
fun initPassw0rdNew(): Protocol {
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
Protocol initPassw0rdNew() {
    ProtocolContext context = ProtocolContext.create(
            "APP_TOKEN_HERE",
            "NEW_SERVICE_PUBLIC_KEY_HERE",
            "NEW_APP_SECRET_KEY_HERE",
            ""); // updateToken needs to be empty

    return new Protocol(context);
}
```

## Docs
* [Virgil Dashboard](https://dashboard.virgilsecurity.com)
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
