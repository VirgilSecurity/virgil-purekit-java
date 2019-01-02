# Passw0rd Kotlin/Java SDK

[![Build Status](https://travis-ci.com/passw0rd/sdk-kotlin.svg?branch=master)](https://travis-ci.com/passw0rd/sdk-kotlin)
[![Maven](https://img.shields.io/maven-central/v/com.virgilsecurity/passw0rd.svg)](https://img.shields.io/maven-central/v/com.virgilsecurity/passw0rd.svg)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and Configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<a href="https://passw0rd.io/"><img width="260px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/passw0rd.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) that provides developers with a technology to protect users passwords from offline/online attacks and make stolen passwords useless even if your database has been compromised.

PHE is a new, more secure mechanism that protects user passwords and lessens the security risks associated with weak passwords. Neither Virgil nor attackers know anything about user password.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.


## Features
- Zero knowledge of user password
- Protection from online attacks
- Protection from offline attacks
- Instant invalidation of stolen database
- User com.virgilsecurity.passw0rd.data encryption with a personal key


## Register Your Account
Before starting practicing with the SDK and usage examples be sure that:
- you have a registered passw0rd account
- you have a registered passw0rd application
- and you got your passw0rd application's credentials, such as: Application ID, Access Token, Service Public Key, Client Secret Key

If you don't have an account or a passw0rd project with its credentials, please use the [passw0rd CLI](https://github.com/passw0rd/cli) to get it.


## Install and Configure SDK
Installing the package using gradle:

```bash
    implementation "com.virgilsecurity:passw0rd:0.1.0"
```


### Configure SDK
Here is an example of how to specify your credentials SDK class instance:
```cs
// specify your account and app's credentials
val context = ProtocolContext.create(
    appId = "58533793ee4f41bf9fcbf178dbac9b3a",
    accessToken = "-KM2dB9-butQv1Op6l0L5TEFy2fL-zty",
    serverPublicKey = "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    clientSecretKey = "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc=")

val protocol = Protocol(context);
```

## Prepare Your Database
Passw0rd SDK allows you to easily perform all the necessary operations to create, verify and rotate user's password without requiring any additional actions.

In order to create and work with user's protected passw0rd you have to set up your database with an additional column.

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

### Enroll User passw0rd

Use this flow to create a new passw0rd record for a user in your DB.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in to your system to implement **passw0rd**. You can go through your database and enroll user's passw0rd at any time.

So, in order to create passw0rd for a new database or an available one, go through the following operations:
- Take user **password** (or its hash or whatever you use) and pass it into the `EnrollAsync` function in SDK on your Server side.
- Passw0rd SDK will send a request to passw0rd service to get enrollment.
- Then, passw0rd SDK will create user passw0rd **record**. You need to store this unique user's `record` (recordBytes or recordBase64 format) in your database in an associated column.

```cs
var password = "passw0rd";

// create a new encrypted passw0rd record using user password or its hash
var record = await protocol.EnrollAsync(password);

// save encrypted passw0rd record into your users DB

var recordBytes = record.Encode();          // encode encrypted password record into bytearray
var recordBase64 = record.EncodeToBase64(); // encode encrypted password record base64 string

// save record into your users DB
```

When you've created a `passw0rd_record` for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User passw0rd

Use this flow at the "sign in" step when a user already has his or her own unique `record` in your database. This function allows you to verify that the password that the user has passed is correct. 
You have to pass his or her `record` from your DB into the `VerifyPassword` function:

```cs
// get user's encrypted password record from your users DB
var passwordCandidate = "passw0rd";

// check candidate password with encrypted password record from your DB
var verifyResult = await protocol.VerifyAsync(record, passwordCandidate);

if (!verifyResult.IsSuccess)
{
    throw new Exception("Authentication failed");
}
```


### Rotate User passw0rd

This function allows you to use a special `UpdateTokens` to rotate users' `record` in your database.

> Use this flow only if your database has been COMPROMISED!
When a user just needs to change his or her own password, use the `enroll` function to replace old user's `passw0rd_record` value in your DB with a new user's `passw0rd_record`.

How it works:
- Get your `UpdateToken` using [passw0rd CLI](https://github.com/passw0rd/cli).
- Specify the `UpdateToken` in the passw0rd SDK on your Server side.
- Then use the `Update` records function to create new user's `record` for your users (you don't need to ask your users to create a new password).
- Finally, save the new user's `record` into your database.

Here is an example of using the `Update` records function:
```cs
// set up the UpdateToken that you got from passw0rd CLI in config
var context = ProtocolContext.Create(
    appId:           "58533793ee4f41bf9fcbf178dbac9b3a",
    accessToken:     "-KM2dB9-butQv1Op6l0L5TEFy2fL-zty",
    serverPublicKey: "PK.1.BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
    clientSecretKey: "SK.1.YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc=",
    updateTokens:    new {
        "UT.2.MEQEIF9FaIoBlwvyV1HuIYw1cEL0GF6TyjJqYpO/b/uzsg88BCB0Cx2dnG8QKFyHr/nTOjQr7qeWgrM7T9CAg0D8p+EvVQ=="
    }
);

var protocol = new Protocol(context);

// get previous user's encrypted passw0rd record from the compromised DB
// update previous user's encrypted passw0rd record and save new one into your DB
var newRecord = protocol.Update(record);
```


## Docs
* [Passw0rd][_passw0rd] home page
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

Also, get extra help from our support team: support@VirgilSecurity.com.

[_passw0rd]: https://passw0rd.io/
