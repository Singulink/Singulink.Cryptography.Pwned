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

This repository is used for our own infrastructure needs and is open-sourced so that others can run the same service. The service runs on your own network, and your apps check passwords against it with the client, which is given the service's address. The instance at https://pwned.singulink.com is there to try the service out, for example in its Swagger UI at https://pwned.singulink.com/swagger, and isn't meant for real use.

The client sends the full SHA-1 hash of each password it checks, unsalted, to the service. That is why the service is for internal use: it runs inside your network, the apps reach it there, and the hashes don't leave the network. The service keeps its own copy of the Pwned Passwords data (see [Running the Service](#running-the-service)), so checks don't call out to Have I Been Pwned either, except for the ranges it doesn't have yet.

## Installation

A client package is available on NuGet - simply install the `Singulink.Cryptography.Pwned.Client` package. It brings in `Singulink.Cryptography.Pwned`, the package with the types that the client and the service share: `CheckPasswordResult`, which the service returns, the error codes in `PwnedErrorCodes` and the JSON serializer context. The client is built on the client library of the [Singulink HTTP API Toolkit](https://github.com/Singulink/Singulink.Net.Http.Api).

**Supported Runtimes**: .NET 10+ and .NET Framework 4.6.2+. Other runtimes that can use .NET Standard 2.0 libraries, such as .NET 8 and 9, get a build warning: they are not supported or tested.

To run the service on your own infrastructure, see [Running the Service](#running-the-service) below.

### Using the Client

`PwnedClient` sends its requests to the service at the address given to its constructor. All clients share one `HttpClient`, so an app usually creates one client and keeps it, for example as a singleton:

```csharp
services.AddSingleton<IPwnedClient>(new PwnedClient(new Uri("https://pwned.example.internal/")));
```

```csharp
int count = await pwnedClient.GetBreachCountAsync(password, cancellationToken);

if (count > 0)
    Console.WriteLine($"The password appears {count} times in breached data.");
```

`GetBreachCountAsync` hashes the password with SHA-1 over its UTF-8 bytes and sends the whole hash to the service's `/CheckPasswordHash` endpoint, which answers with the number of times the password appears in the data, or `404` with the `password-not-found` error code when it doesn't appear. The client returns 0 for that `404` and throws for any other, such as one from an address that isn't the service's. The client only takes passwords, not hashes.

Errors that the service returns are thrown as the toolkit's `ApiException` types, with the service's message, error code and `Retry-After` time (see [Errors](#errors)), and `ApiFailures.IsTransient` tells whether a failure is worth trying again. A request times out after 15 seconds. The constructor that takes an `HttpMessageHandler` sends the client's requests through it, for example to answer them in tests with `ApiErrorResponse.Create`.

Version 3.0 of the client changes how it is created, what it is called with and how it reports errors:

- It needs version 3.0 of the service, which marks its "not in the data" `404` with the `password-not-found` error code: the 3.0 client throws for a `404` without it. Clients before 3.0 ignore the body of a `404`, so the service can be updated first, and the clients after it.
- The service's address is passed to the constructor, which has no default. `PwnedClient.DefaultBaseAddress`, the parameterless constructor and the constructor that takes an `IHttpClientFactory` are gone.
- Errors are thrown as `ApiException` types instead of `HttpRequestException`s, and the message no longer contains the error code. Failures to reach the service are still `HttpRequestException`s, and timeouts `TaskCanceledException`s.
- `CheckPasswordAsync` and `CheckPasswordHashAsync` are replaced by `GetBreachCountAsync`, which takes the password and a `CancellationToken` and returns the count, or 0 when the password isn't in the data: `CheckPasswordAsync(password) is not null` becomes `GetBreachCountAsync(password) > 0`. There is no method that takes a hash.
- `PwnedClient` is sealed, and `CheckPasswordResult` is in the `Singulink.Cryptography.Pwned` package.

Note: The service's `/CheckPassword` endpoint takes the password itself, unhashed, in its query string, instead of its hash. The client never uses it: it is there to try the service out in its Swagger UI. The `CheckPasswordEndpointEnabled` setting turns it off (see [Configuration](#configuration)).

## Running the Service

`Singulink.Cryptography.Pwned.Service` is a .NET 10 web service that can be hosted in IIS, Azure, or any other suitable .NET hosting environment. It doesn't need a database: it downloads the Pwned Passwords data from the [Have I Been Pwned range API](https://haveibeenpwned.com/API/v3#PwnedPasswords) into a folder of files and keeps it up to date by itself. It answers lookups from the moment it starts, even with an empty data folder.

### How It Works

Have I Been Pwned splits the Pwned Passwords data into 1,048,576 ranges by the first 5 hex digits of the SHA-1 hash. The service stores each range in its own small binary file in the data folder (`ranges/A1B/2C.bin` for range `A1B2C`, about 2,000 hashes each), and a lookup reads about 4 KB from a single file, so lookups are fast without any index or database.

A sync pass checks every range with Have I Been Pwned using conditional requests and only downloads the ranges that changed, so a pass where nothing changed takes about 15 minutes and transfers well under 1 GB. The service runs a pass right after it starts if any ranges are missing or no pass has completed yet, and otherwise once a week. A pass that is interrupted (for example by a restart) continues where it stopped, and ranges that couldn't be downloaded are tried again after the retry interval. Every range file is written to a temp file, flushed to disk and then renamed over the old one, so a range file is always either the old version or the complete new one, even after a power loss. Downloads are checked against the `Content-MD5` header that Have I Been Pwned sends.

A lookup in a range that isn't stored yet, or whose file is invalid (for example in a damaged copy of the data folder) or can't be read, downloads that range on the spot (a range is only a few dozen KB), answers from the download and stores the range in the data folder. Lookups in the same range share one download, at most 16 ranges are downloaded this way at a time, and a download finishes and is stored even if the client that asked for it disconnects. Only if the range can't be downloaded, for example because Have I Been Pwned is unreachable or doesn't answer within 10 seconds, does the lookup return `503 Service Unavailable`, with the `hibp-unavailable` error code and a `Retry-After` header of 60 seconds, which the client throws as a `ServiceUnavailableApiException` with the error code in `ErrorCode` and the time in `RetryAfter`.

So the service doesn't need a filled data folder to answer lookups. The sync fills an empty one in the background: that downloads about 40 GB and takes roughly half an hour on a fast connection.

### Requirements

- About 50 GB of disk space for the data folder. An SSD or a disk with a write-back cache (such as a battery-backed RAID controller) is recommended for the initial download, since each of the million files is flushed to disk.
- Outbound HTTPS access to `api.pwnedpasswords.com`, and to `www.cloudflare.com` for Cloudflare's IP ranges (see [Cloudflare](#cloudflare)).
- Modify permission on the data folder for the identity the service runs as, e.g. the IIS app pool identity (`IIS AppPool\<app pool name>`). Write permission alone isn't enough on Windows, because replacing a range file needs delete permission.
- Exclude the data folder from antivirus real-time scanning. A pass writes thousands of small files per minute and lookups read them all the time.

### Configuration

Settings are read from the `Pwned` configuration section, so you can put them in `appsettings.json` or set them with environment variables like `Pwned__DataDirectory`:

| Setting | Default | Description |
| --- | --- | --- |
| `DataDirectory` | (required) | The folder for the range files, about 50 GB in a million files (see [Requirements](#requirements)). It has no default. Relative paths are resolved against the content root. Keep it outside the site's folder so deployments don't touch it. |
| `SyncEnabled` | `true` | Whether this instance syncs the data folder: downloads every range and checks them all for changes every `SyncInterval`. |
| `OnDemandDownloadEnabled` | `true` | Whether lookups download ranges that aren't stored yet or whose files are invalid. Turn it off on instances that must never call out, such as ones that share a read-only data folder kept up to date by another instance. Lookups in missing ranges then return `503`. |
| `CheckPasswordEndpointEnabled` | `true` | Whether the `/CheckPassword` endpoint exists. It takes the password itself, unhashed, in its query string, so that the service can be tried out in its Swagger UI; the client sends the hash to `/CheckPasswordHash` instead. When `false`, the endpoint isn't mapped and isn't in the OpenAPI document. |
| `SyncInterval` | `7.00:00:00` | How often every range is checked for changes. |
| `RetryInterval` | `00:15:00` | How long to wait before trying again after a pass fails (e.g. Have I Been Pwned is unreachable) or leaves ranges missing or out of date. |
| `DownloadConcurrency` | `32` | The number of ranges a sync pass downloads in parallel (1-256). |

The service won't start without a `DataDirectory` and says so in the startup error. Sync progress and pass summaries are logged at the `Information` level and failures as warnings. Failed on-demand downloads and writes are logged as warnings too, but at most once a minute each, with a count of the ones that weren't logged.

The service has no secrets to configure. The rate limit and Cloudflare settings below are in their own configuration sections.

### Errors

Errors use the [error format](https://www.singulink.com/Docs/Singulink.Net.Http.Api/articles/concepts/error-format.html) of the Singulink HTTP API Toolkit: the status code and a `text/plain` message. Some errors have an error code in square brackets in front of the message, and their content type has a `format=error-code` parameter. The client returns 0 for the `password-not-found` `404` and throws the toolkit's exception for every other error: `BadRequestApiException`, `NotFoundApiException`, `TooManyRequestsApiException`, `ServerErrorApiException` or `ServiceUnavailableApiException`, with the message, the error code in `ErrorCode` and the `Retry-After` time in `RetryAfter`. Clients before version 3.0 throw an `HttpRequestException` with the whole response body as its message, error code included:

| Status | Message | Returned when |
| --- | --- | --- |
| `400` | `Password hash should be 40 hex characters.` | The hash isn't 40 hex digits. |
| `400` | `The request is not valid.` | A required query parameter is missing. |
| `404` | `[password-not-found] The password isn't in the Pwned Passwords data.` | The password isn't in the data. The client returns 0 for it. |
| `429` | `[rate-limited] Too many requests. Please wait a moment and try again.` | The client made too many requests (see [Rate Limit](#rate-limit)). |
| `500` | `An unexpected error has occurred and has been logged. Reference ID: {id}.` | Something unexpected failed. The error is logged with the same reference ID. |
| `503` | `[hibp-unavailable] The password hash's range couldn't be downloaded from Have I Been Pwned. Please try again later.` | The hash's range isn't stored and couldn't be downloaded. |
| `503` | `[range-not-downloaded] The password hash's range hasn't been downloaded yet. Please try again later.` | The hash's range isn't stored and `OnDemandDownloadEnabled` is off. |
| `503` | `[cloudflare-ranges-unavailable] The service is starting. Please try again shortly.` | The service has no Cloudflare IP ranges yet (see [Cloudflare](#cloudflare)). |

The `429` and `503` responses have a `Retry-After` header with the number of seconds to wait: until the next rate limit window, 60 for a range and 10 for Cloudflare's ranges.

### Rate Limit

Each client with a public address can make 50 requests a minute, counted in windows that start at every full minute, and IPv6 clients are counted per /64 network. The limit is for the public instance, which is there to try the service out. Clients with private addresses aren't limited: private IPv4 networks, loopback, link-local, the shared address space (`100.64.0.0/10`), unique local IPv6 addresses and connections without an address. So a deployment inside a private network, whose apps reach it from such addresses, isn't limited. A request over the limit gets a `429` error (see [Errors](#errors)). The `RateLimits` settings below change the limit.

This is the [per-client rate limit](https://www.singulink.com/Docs/Singulink.Net.Http.Api/articles/guides/rate-limiting.html) of the Singulink HTTP API Toolkit, with its settings in the `RateLimits` configuration section, for example `RateLimits__PermitLimit` as an environment variable:

| Setting | Default | Description |
| --- | --- | --- |
| `PermitLimit` | `50` | The number of requests each client address can make per window. |
| `Window` | `00:01:00` | The length of a window. |
| `ExemptPrivateNetworks` | `true` | Whether clients with private addresses are exempt. |
| `ExemptNetworks` | (none) | Other addresses, or networks in CIDR notation, whose clients are exempt, such as `RateLimits__ExemptNetworks__0=203.0.113.7`. |
| `Enabled` | `true` | Whether requests are limited at all. |

Each server counts the requests it gets, so in a web farm a client can make up to the limit on each server.

### Cloudflare

The service can run behind Cloudflare's proxy. For a request whose connection comes from one of [Cloudflare's IP ranges](https://www.cloudflare.com/ips/), the service takes the client's address from Cloudflare's `CF-Connecting-IP` header and the scheme from `X-Forwarded-Proto`, so the rate limit counts each client rather than Cloudflare's servers. All other requests keep their connection's address and scheme, and any headers starting with `CF-` are removed from them, so the service can be reached through Cloudflare and directly at the same time. This is the [Cloudflare forwarding](https://www.singulink.com/Docs/Singulink.Net.Http.Api/articles/guides/cloudflare.html) of the Singulink HTTP API Toolkit.

The service downloads Cloudflare's IP ranges at startup and once a day, and saves them to `cloudflare-ip-ranges.txt` in the data folder. When the download at startup fails, it uses that saved copy. Without any ranges, as on a first start that can't download them, the service refuses every request with a `503` error (`cloudflare-ranges-unavailable`) and tries the download again every 10 seconds, until it succeeds.

The settings are in the `Cloudflare` configuration section, for example `Cloudflare__SavedRangesPath` as an environment variable (see the [toolkit's documentation](https://www.singulink.com/Docs/Singulink.Net.Http.Api/articles/guides/cloudflare.html#options) for all of them):

| Setting | Default | Description |
| --- | --- | --- |
| `SavedRangesPath` | `cloudflare-ip-ranges.txt` in the `DataDirectory` folder | Where the downloaded ranges are saved. Relative paths are resolved against the content root. |
| `TrustedProxyNetworks` | (none) | Addresses, or networks in CIDR notation, of other proxies whose connections are trusted like Cloudflare's, such as `Cloudflare__TrustedProxyNetworks__0=127.0.0.1` for Cloudflare Tunnel's `cloudflared` on the same machine. |
| `DownloadRanges` | `true` | Whether the ranges are downloaded. When `false`, they are only read from `SavedRangesPath`, at startup and every `RefreshInterval`. |
| `RefreshInterval` | `1.00:00:00` | How often the ranges are downloaded again. |

### Hosting in IIS

The sync runs inside the service, so IIS has to keep the service running even when there are no requests. Lookups would still work without that, but the initial fill and the weekly sync would only run while requests keep the service alive:

- Set the app pool's **Start Mode** to `AlwaysRunning` and its **Idle Time-out** to `0`.
- Set the site's **Preload Enabled** to `True`. This needs IIS's Application Initialization feature (`Web-AppInit`), which isn't installed by default.

App pool recycles are fine: a pass interrupted by a recycle continues where it stopped once the new worker process has started.

Behind Cloudflare, IIS needs no changes for the client addresses, since the service reads Cloudflare's headers itself. IIS's own logs still show the addresses of Cloudflare's servers.

### Web Farms

Each server can sync its own data folder, or all servers can share one folder on a file share: each server's `DataDirectory` is then set to the share, and `SyncEnabled` is turned off on every server except one. Only one process can sync a data folder at a time: a `sync.lock` file in the folder is held open without sharing during a pass, so a second syncing instance just skips its passes and tries again later. That also works across Windows servers over SMB, but Linux SMB clients may not enforce it, so don't rely on it there.

Every instance downloads ranges on demand into the folder it uses, including instances with `SyncEnabled` off. That doesn't need the sync lock: each write goes to a uniquely named temp file that is then renamed over the range file, so instances that share a folder don't get in each other's way. If an instance can only read a shared folder, turn `OnDemandDownloadEnabled` off on it as well. Such an instance can't save Cloudflare's IP ranges in the folder either, so it logs a warning each time it downloads them, unless `Cloudflare:SavedRangesPath` points to a file it can write (see [Cloudflare](#cloudflare)). Servers with `SyncEnabled` off report the number of ranges stored as of their startup, plus the ones they downloaded on demand since, in `/Status`.

To set up another server with its own data folder, you can copy the data folder of a running instance and point the new instance's `DataDirectory` at the copy. Range files are only ever replaced whole, and the new instance checks the files it reads and downloads any that turn out to be invalid again.

### Status

`GET /Status` returns the number of ranges stored (`null` until the service has scanned its data folder after starting), whether a pass is running and its progress, the time the last pass over every range completed, when the next pass is due, and how many ranges this instance downloaded on demand and how many of those downloads failed since it started:

```json
{
  "rangesStored": 1048576,
  "totalRanges": 1048576,
  "syncEnabled": true,
  "syncRunning": false,
  "currentPass": null,
  "lastCompletedPass": "2026-10-21T12:41:08.8306052+00:00",
  "nextPass": "2026-10-28T12:13:27.1597140+00:00",
  "onDemandDownloadEnabled": true,
  "onDemandDownloads": 2214,
  "onDemandFailures": 0
}
```

### Upgrading from the Database Version

Earlier versions of the service looked up hashes in a SQL Server database that you imported the data into by hand. The new version answers every lookup from the start by downloading ranges on demand, and fills its data folder in the background, so there is nothing to prepare:

1. Set `Pwned__DataDirectory` for the site to a new, empty data folder, as an environment variable that publishing doesn't overwrite (e.g. one of the app pool's environment variables), and give the app pool identity Modify permission on the folder. Do this before publishing: the old version ignores the setting, and the new version won't start without it.
2. Publish the new version over the old deployment.
3. Set the app pool's **Start Mode** to `AlwaysRunning` and its **Idle Time-out** to `0`, and the site's **Preload Enabled** to `True` (see [Hosting in IIS](#hosting-in-iis)), so the initial fill and the weekly sync keep running when there are no requests.
4. Delete the old database and its `PwnedDatabase` connection string.

For a second instance with its own data folder, you can start from a copy of the first instance's data folder instead of an empty one. Copying it while the first instance is running is fine.

### Data License

The Pwned Passwords data is provided by [Have I Been Pwned](https://haveibeenpwned.com/Passwords) under the [Creative Commons Attribution 4.0 International license (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). Thanks to Troy Hunt and everyone who contributes to it!

## Tests

`dotnet test` runs every test except the ones that call the live service at https://pwned.singulink.com, which have the `Live` test category. They need version 3.0 of the service there, since the client takes a `404` without the `password-not-found` error code for an error. The client's test project leaves them out with `Tests/Singulink.Cryptography.Pwned.Tests/ExcludeLiveTests.runsettings`, which its `RunArguments` pass to the test runner unless the `RunLiveTests` MSBuild property is `true`.

This runs all the tests, the live ones included:

```sh
dotnet test -p:RunLiveTests=true
```

This runs only the live tests, from the `Tests/Singulink.Cryptography.Pwned.Tests` folder:

```sh
dotnet test -p:RunLiveTests=true --filter "TestCategory=Live"
```
