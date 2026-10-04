# S3

`ecosystem::s3` is a synchronous S3-compatible object client written in GoML.
It uses `ecosystem::request` for HTTP/TLS, `ecosystem::xml` for bounded protocol
parsing, `ecosystem::datetime` for UTC timestamps, and the standard SHA-256/HMAC
implementations for AWS Signature Version 4. Requires GoML 0.1.57 or newer.

The initial API supports ordinary regional S3 buckets and compatible endpoints:

- Signed GET, HEAD, PUT and DELETE object requests.
- ListObjectsV2, prefixes, delimiters, continuation tokens, URL-encoded keys and
  bounded callback-based pagination.
- Presigned GET, HEAD, PUT and DELETE URLs, with expiry from 1 to 604800 seconds.
- Multipart initiation, numbered part upload, completion and abort; a bounded
  chunk-source convenience method aborts on error, cancellation or callback panic.
- Explicit region/endpoint configuration, path or virtual-host addressing,
  temporary session credentials, and an injectable credential provider and clock.

## Upload and download

```goml
use ecosystem::s3;
use std::bytes::Bytes;
use std::context::Context;

fn store(access_key: string, secret_key: string) -> Result[Bytes, s3::Error] {
    let credentials = s3::Credentials::new(access_key, secret_key)?;
    let client = s3::Client::new(s3::Config::aws("us-east-1"), credentials)?;
    defer client.close();
    let context = Context::background();
    client.put_object(
        context, "example-bucket", "reports/latest.txt",
        Bytes::from_string("report"), "text/plain",
    )?;
    Result::Ok(client.get_object(context, "example-bucket", "reports/latest.txt")?.body)
}
```

`get_object` returns owned bytes, ETag, version ID, content type and response
headers. `head_object` returns the declared object size and the same metadata.
`put_object` returns an optional ETag; `delete_object` returns `Result[(), Error]`.
ETags remain opaque strings, including quotes; they are not interpreted as MD5.

`Config::aws(region)` uses HTTPS and virtual-host addressing at
`s3.<region>.amazonaws.com`. Use `Config::endpoint(origin, region)` for another
AWS partition, MinIO, or another compatible service; it defaults to path
addressing. Endpoints must be origins, without path prefixes, queries, fragments
or credentials. Plain HTTP requires explicitly setting `allow_http: true`.
Virtual-host mode requires a DNS endpoint without an explicit port. Dotted
bucket names require path addressing with HTTPS to avoid wildcard-certificate
mismatches. TLS verification always remains enabled.

All client operations accept `std::context::Context`. Reuse a client to retain
the request connection pool, and close it when finished. Cancellation covers
network I/O and checks between pages and parts. Providers and chunk callbacks
must cooperate with cancellation for any blocking work of their own.

## Credentials and signing

`Credentials::new(access_key, secret_key)` validates nonempty bounded values.
`with_session_token(token)` supports temporary credentials. Their `Debug` output
is redacted. `Client::with_provider(config, provider)` calls
`(Context) -> Result[Credentials, Error]` before each request or presigning call,
so an application can refresh credentials without rebuilding the client.
Provider errors become a fixed credential error; their text is not propagated.
Providers used concurrently must synchronize their own mutable state.

There is no implicit environment, shared-credentials-file, metadata-service,
STS or web-identity credential chain. Applications explicitly supply their own
provider. No credentials or default account settings are built into this module.

`Config.clock` is `() -> string`, returning a UTC timestamp in
`YYYYMMDDTHHMMSSZ` form. Its default uses the system clock; an injected clock makes
signing deterministic. Invalid calendar dates fail before sending a request.
Non-ASCII digits and malformed timestamps return configuration errors as well.

The lower-level `SigningRequest`, `sign` and `presign_query` APIs are public for
testing or alternate transports. `SigningRequest.path` is the **raw, decoded
absolute path**, and query pairs are **decoded names and values**. A literal `%`
therefore becomes `%25`. The signer percent-encodes UTF-8 bytes with uppercase
hex, encodes query spaces as `%20`, sorts encoded names and then encoded values,
retains duplicate parameters, combines repeated headers and normalizes header
whitespace. It preserves repeated slashes and dot segments in S3 keys. `host`
must be the exact authority sent on the wire, including a nondefault port.

`Signature` exposes canonical request text and signed headers for inspection.
Those fields can contain a session token and must be treated as credentials.
They deliberately have no automatic `Debug` implementation. Presigned URLs are
also bearer capabilities and should not be logged. `presign_query` uses
`UNSIGNED-PAYLOAD`; applications using extra signed headers must send those
headers with the resulting URL. The higher-level `Client.presign` signs only
the host. Temporary credentials can expire before a requested URL expiry.

Every client request disables redirects, including same-origin redirects, so
authorization and session-token headers are never forwarded to a redirect
target. A regional redirect is reported as a service error; correct the region
or endpoint and issue a newly signed request. Environment proxies and automatic
gzip decoding are disabled so object bytes retain their original representation.

## Listing

`ListOptions::new()` requests up to 1000 keys. Its public fields are `prefix`,
`delimiter`, `continuation_token` and `max_keys` (1 through 1000).
`list_objects` returns one `ListPage` with `objects`, `common_prefixes` and
`next_token`. Keys and prefixes are URL-decoded when the response specifies URL
encoding; continuation tokens are opaque and are never URL-decoded as keys.

`list_pages(context, bucket, options, max_pages, consume)` invokes
`(ListPage) -> Result[bool, Error]` once per page and returns the page count.
Return `false` to stop early. It detects repeated tokens and fails when another
page would exceed `max_pages`, avoiding unbounded enumeration. It retains only
the token history, bounded by 100000 pages and the metadata byte budget; consumers decide whether to retain
object records. Missing/duplicate scalar fields, invalid numbers, DTDs, external/custom entities,
unrecognized namespaces and malformed XML produce recoverable protocol errors.

## Multipart uploads

`create_multipart(context, bucket, key, content_type)` returns a `MultipartUpload`.
Use `upload_part(context, number, bytes)` to obtain a `CompletedPart`; number is
1 through 10000. Pass unique, ascending completed parts to
`complete(context, parts)`, or call `abort(context)`. Keep the returned ETags;
the client XML-escapes them when completing. A completion response with HTTP 200
and an XML `Error` is still an error. Low-level multipart callers own cleanup,
part ordering, part sizes and their application state.

`upload_multipart(context, bucket, key, content_type, part_size, next)` offers
managed cleanup. `next` returns `Result[Option[Bytes], Error]`; `None` ends the
source. `part_size` is at least 5 MiB and no larger than `max_object_bytes`.
Each chunk must be nonempty, no larger than `part_size`, and all chunks except
the final one must be at least 5 MiB. The method uploads sequentially, holds one
chunk at a time plus bounded request snapshots, and retains at most 10000 ETags.
Use `put_object` for an empty object.

On failure, managed uploads attempt abort under a fresh 10-second cleanup
context even when the original context was cancelled. `Error.cleanup_failed`
reports failure of that attempt. A callback panic is rethrown after attempting
abort; a cleanup panic cannot replace the original panic. No library can
guarantee remote cleanup during a network outage or process termination, so
configure the bucket's incomplete-multipart lifecycle rule as appropriate.

## Bounds and errors

The default per-object/request/part budget is 64 MiB, adjustable from 1 byte to
1 GiB. GET and ordinary PUT are buffered within this limit; they are not
unbounded streaming APIs. Multipart provides the bounded upload path for larger
objects. The default metadata response budget is 1 MiB, configurable up to
16 MiB. XML parsing also caps depth (16), attributes per element (16) and tokens
(20000). Signing limits decoded header/query metadata to 64 KiB, 100 headers and
1000 query pairs. Object keys contain 1 through 1024 UTF-8 bytes. Request timeout
defaults to 30 seconds; the supplied context can bound the overall operation.

`Error` distinguishes configuration, credential, cancellation, transport, limit,
protocol and service failures. Service errors retain the HTTP status and only
recognized S3 error codes; unfamiliar codes become `UnknownServiceError`.
Server messages, response bodies, signed URLs, provider errors and lower-level
transport diagnostics are not copied into errors. Caller-created callback errors
remain the caller's responsibility. There are no automatic retries.

The initial scope excludes bucket administration, ACLs/policies, explicit
version selection, copy operations, conditional/range requests, encryption
options, checksums beyond signed SHA-256 payloads, AWS chunk-signing,
presigned browser POST, automatic region discovery, access-point/Outposts/Express
endpoints and SigV4a. Compatibility with every third-party service is not claimed.

## Verification and protocol references

Run `goml fmt --check`, `goml test` and `goml verify --timeout 300s` from the
module root. `goml test` includes AWS's four published header-signing vectors,
its presigning vector, canonicalization/security negative tests, and local HTTP
integration tests. The HTTP fixture uses Python 3's standard `hashlib`/`hmac` and
HTTP server to independently check received paths, queries, headers and payload
signatures. It covers CRUD, temporary credentials, presigned requests, pagination,
multipart, embedded errors, cancellation, body budgets and redirect isolation.
Tests start the fixture within a task scope and terminate it on unwind. They need
Python 3, but need no external service, AWS account or real credentials.
`examples/basic` and its independent consumer test exercise the public API.

Protocol references:

- [AWS SigV4 canonicalization and signing vectors](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html)
- [AWS presigned URL signing](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html)
- [ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html)
- [CreateMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html), [UploadPart](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html), [CompleteMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html), [AbortMultipartUpload](https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html)
