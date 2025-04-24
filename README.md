# Singulink.Cryptography.Pwned

[![Chat on Discord](https://img.shields.io/discord/906246067773923490)](https://discord.gg/EkQhJFsBu6)
[![View nuget packages](https://img.shields.io/nuget/v/Singulink.Cryptography.Pwned.Client.svg)](https://www.nuget.org/packages/Singulink.Cryptography.Pwned.Client/)
[![Build and Test](https://github.com/Singulink/Singulink.Cryptography.Pwned/workflows/build%20and%20test/badge.svg)](https://github.com/Singulink/Singulink.Cryptography.Pwned/actions?query=workflow%3A%22build+and+test%22)

**Singulink.Cryptography.Pwned** is a .NET project that contains a simple client and server for checking if passwords have been compromised in a data breach using the [Have I Been Pwned](https://haveibeenpwned.com/) database. It provides a simple and efficient way to verify the security of passwords against a large database of known compromised passwords.

There are limited benefits (and several drawbacks) to using this library if you do not intend to self-host the service internally - you are much better off using any one of the many other available .NET client libraries that call into the official [Have I Been Pwned API](https://haveibeenpwned.com/API/v3) service in that case.

If you are looking to self-host you are in the right place, so continue on! :)

### About Singulink

We are a small team of engineers and designers dedicated to building beautiful, functional, and well-engineered software solutions. We offer very competitive rates as well as fixed-price contracts and welcome inquiries to discuss any custom development / project support needs you may have.

This package is part of our **Singulink Libraries** collection. Visit https://github.com/Singulink to see our full list of publicly available libraries and other open-source projects.

## Usage

This repository is used for our own infrastructure needs but is open-sourced so anyone else who wants to host an internal pwned password checking service to avoid calling out to an external service can easily do so. You are welcome to use the client without running your own service for testing (the client defaults to using our publicly accessible service), and while you *can* use our service in production, you are encouraged to host your own service for that purpose. You can take our API for a test drive at https://pwned.singulink.com/swagger.

If you do use our publicly available service, we kindly ask that you limit usage to testing and/or checking passwords during actual user interactions like registration / login / password changes, and not for anything that involves bulk checking of passwords. If you have a high-volume application or need to check large numbers of passwords for a different purpose, please run your own instance of the service or download the Pwned data locally and run your checks against that.

## Installation

A client package is available on NuGet - simply install the `Singulink.Cryptography.Pwned.Client` package.

**Supported Runtimes**: Everywhere .NET Standard 2.0 is supported, including:
- .NET
- .NET Framework
- Mono / Xamarin

End-of-life runtime versions that are no longer officially supported are not tested or supported by this library.

For running the service on your own infrastructure, deploy `Singulink.Cryptography.Pwned.Service` to your desired hosting destination. The project is a .NET 9.0 web service that can be hosted in IIS, Azure, or any other suitable .NET hosting environment. You will need to configure your own database connection string in `appsettings.json` and import the Pwned passwords into a `Passwords` table with `Hash` and `Count` columns. It is currently setup for MSSQL but any EF Core provider can be used. At the time of this writing, importing pwned data into a database results in a data file that is ~80GB in size.

You can point the client to your own service by setting `PwnedClient.ApiBaseUri` to the URL of your service.

Note: While the service contains a `/CheckPassword` endpoint that allows you to pass in an actual password instead of pre-hashing it, the client library never uses that endpoint - it should only be used for testing or when querying against a locally running service. The `PwnedClient.CheckPasswordAsync` method hashes passwords client-side using SHA1 before calling the `/CheckPasswordHash` endpoint so that the password is never sent over the wire. You can safely remove or disable the `/CheckPassword` endpoint without affecting applications that use the client library.