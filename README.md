# Virgil KeyKnox Java/Android SDK

[Introduction](#introduction) | [SDK Features](#sdk-features) | [Install and configure SDK](#install-and-configure-sdk) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides an SDK which allows you to communicate with Virgil Keyknox Service.
Virgil Keyknox Service allows users to store their sensitive data (such as Private Key) encrypted (with end-to-end encryption) for using and sharing it between different devices.

## SDK Features
- use [Virgil Crypto library][_virgil_crypto]
- use [Virgil SDK][_virgil_sdk]
- upload encrypted sensitive data to Virgil Keyknox Service
- download the data from Virgil Keyknox Service
- update and synchronize the data

## Install and configure SDK

### Installation

Virgil Keyknox SDK is provided as a set of frameworks. These frameworks are distributed via Carthage and CocoaPods. Also in this guide, you find one more package called VirgilCrypto (Virgil Crypto Library) that is used by the SDK to perform cryptographic operations.

TheVirgil Keyknox SDK is provided as a package named com.virgilsecurity.keyknox. The package is distributed via Maven repository.

The package is available for:
- Java 8 and newer
- Android API 16 and newer

Prerequisites:
- Java Development Kit (JDK) 8+
- Gradle 4+

You can easily add SDK dependency to your project, just follow the examples below.

### Install SDK Package

#### Maven

[Apache Maven](https://maven.apache.org/) is a software project management and comprehension tool.

To integrate Virgil Keyknox SDK into your Java project using Maven, set up dependencies in your `pom.xml`:

```xml
<dependencies>
    <dependency>
        <groupId>com.virgilsecurity</groupId>
        <artifactId>keyknox</artifactId>
        <version>0.1.0</version>
    </dependency>
</dependencies>
```

#### Gradle

[Gradle](https://gradle.org/) is an open-source build automation system that builds upon the concepts of Apache Ant and Apache Maven and introduces a Groovy-based domain-specific language (DSL) instead of the XML form used by Apache Maven for declaring the project configuration.

##### Server

To integrate Virgil Keyknox SDK into your Java project using Gradle, set up dependencies in your `build.gradle`:

```
dependencies {
    compile 'com.virgilsecurity:keyknox:0.1.0'
}
```

##### Android

To integrate Virgil Keyknox SDK into your Android project using Gradle, add jcenter() repository if missing:

```
repositories {
    jcenter()
}
```

Set up dependencies in your `build.gradle`:

```
dependencies {
    implementation 'com.virgilsecurity.sdk:crypto-android:5.0.4@aar'
    implementation ('com.virgilsecurity:keyknox:0.1.0') {
        exclude group: 'com.virgilsecurity.sdk', module: 'crypto'
    }
}
```

### Configure SDK

To begin using Virgil Keyknox SDK you'll need to initialize `SyncKeyStorage` class. This class is responsible for synchronization between Keychain and Keyknox Cloud.
In order to initialize `SyncKeyStorage` class you'll need the following values:
- `accessTokenProvider`
- `public keys` of all devices/users that should have access to data
- `private key` of current device/user
- `identity` of the user (the device can have different users)

```java
// Setup Access Token provider to provide access token for Virgil services
// Check https://github.com/VirgilSecurity/virgil-sdk-java-android
val accessTokenProvider = ...

// Download public keys of users that should have access to data from Virgil Cards service
// Check https://github.com/VirgilSecurity/virgil-sdk-java-android
val publicKeys = ...

// Load private key from Keychain
val privateKey = ..

val syncKeyStorage = SyncKeyStorage(identity = "Alice", accessTokenProvider = accessTokenProvider,
        publicKeys = publicKeys, privateKey = privateKey)
```

## Docs
Virgil Security has a powerful set of APIs, and the documentation below can get you started today.

* [Virgil Security Documentation][_documentation]

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.slack.com/join/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).

[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto
[_virgil_sdk]: https://github.com/VirgilSecurity/virgil-sdk-java-android
[_documentation]: https://developer.virgilsecurity.com/
[_dashboard]: https://dashboard.virgilsecurity.com/
