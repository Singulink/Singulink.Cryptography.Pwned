# Singulink.Cryptography.Pwned

[![Chat on Discord](https://img.shields.io/discord/906246067773923490)](https://discord.gg/EkQhJFsBu6)
[![View nuget packages](https://img.shields.io/nuget/v/Singulink.Cryptography.Pwned.Client.svg)](https://www.nuget.org/packages/Singulink.Cryptography.Pwned.Client/)
[![Build and Test](https://github.com/Singulink/Singulink.Cryptography.Pwned/workflows/build%20and%20test/badge.svg)](https://github.com/Singulink/Singulink.Cryptography.Pwned/actions?query=workflow%3A%22build+and+test%22)

**Singulink.Cryptography.Pwned**  a .NET project that contains a client and server for checking if a password has been compromised in a data breach using the [Have I Been Pwned](https://haveibeenpwned.com/) database. It provides a simple and efficient way to verify the security of passwords against a large database of known compromised passwords. You can use the client without running your own service - our publicly available service is hosted at [https://pwned.singulink.com](https://pwned.singulink.com) and the client defaults to using this service.

### About Singulink

We are a small team of engineers and designers dedicated to building beautiful, functional, and well-engineered software solutions. We offer very competitive rates as well as fixed-price contracts and welcome inquiries to discuss any custom development / project support needs you may have.

This package is part of our **Singulink Libraries** collection. Visit https://github.com/Singulink to see our full list of publicly available libraries and other open-source projects.

## Installation

For checking passwords using the client, a package is available on NuGet - simply install the `Singulink.Cryptography.Pwned.Client` package.

**Supported Runtimes**: .NET 9.0+

For running the service on your own infrastructure, deploy `Singulink.Cryptography.Pwned.Server` to your desired hosting destination. The project is a .NET 9.0+ web service that can be hosted in IIS, Azure, or any other .NET hosting environment. You will need to configure your own database connection string in `appsettings.json` and import the Pwned passwords into your database. You can point the client to your service by setting `PwnedClient.ApiBaseUri` to the URL of your service.