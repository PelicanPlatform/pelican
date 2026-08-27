# Pelican HTTP Headers

This document describes the custom HTTP headers used throughout the Pelican platform for communication between clients, directors, origins, caches, and other components.

## Table of Contents

- [Request Headers](#request-headers)
  - [X-Pelican-Timeout](#x-pelican-timeout)
  - [X-Pelican-JobId](#x-pelican-jobid)
  - [X-Pelican-Debug](#x-pelican-debug)
  - [X-Pelican-User](#x-pelican-user)
  - [X-Transfer-Status](#x-transfer-status)
  - [X-Pelican-Object-Metadata](#x-pelican-object-metadata)
- [Response Headers](#response-headers)
  - [X-Pelican-Authorization](#x-pelican-authorization)
  - [X-Pelican-Token-Generation](#x-pelican-token-generation)
  - [X-Pelican-Namespace](#x-pelican-namespace)
  - [X-Pelican-Broker](#x-pelican-broker)
  - [X-Pelican-JobId](#x-pelican-jobid-response)
  - [X-Transfer-Status](#x-transfer-status-trailer)
  - [X-Pelican-Metadata-Status](#x-pelican-metadata-status)
  - [X-Pelican-Metadata-Query-Url / X-Pelican-Metadata-Manage-Url](#x-pelican-metadata-query-url--x-pelican-metadata-manage-url)
- [Metadata Webhook Headers (Origin → External Catalog)](#metadata-webhook-headers-origin--external-catalog)
  - [X-Pelican-Idempotency-Key](#x-pelican-idempotency-key)
- [Other Headers](#other-headers)
  - [X-CSRF-Token](#x-csrf-token)

---

## Request Headers

Headers sent by clients or components making requests.

### X-Pelican-Timeout

**Direction:** Client → Director/Cache/Origin

**Purpose:** Specifies the timeout duration for the request.

**Format:** Duration string (e.g., `5s`, `100ms`, `1m30s`)

**Description:** This header allows clients to specify how long they are willing to wait for a response. The server uses this to set context timeouts and manage request lifecycles. If parsing fails, the header is ignored and a default timeout may be used.

**Example:**

```
X-Pelican-Timeout: 9.5s
```

**Related Code:**

- Used in client requests to director, cache, and broker
- Parsed using Go's `time.ParseDuration()`
- Can also be specified as a query parameter `pelican.timeout`

---

### X-Pelican-JobId

**Direction:** Client → Director/Cache/Origin

**Purpose:** Provides a unique identifier for tracking requests through the system.

**Format:** UUID string

**Description:** This header is used for request correlation and debugging. It allows administrators to trace a request as it flows through various Pelican components (client → director → cache/origin). The same job ID is propagated through all related requests.

**Example:**

```
X-Pelican-JobId: 550e8400-e29b-41d4-a716-446655440000
```

**Related Code:**

- Set by clients on initial requests
- Propagated to subsequent requests (e.g., HEAD requests before downloads)
- Can be extracted from context with canonical header key lookup

---

### X-Pelican-Debug

**Direction:** Client → Director

**Purpose:** Enables debug mode for the request.

**Format:** Boolean string (`"true"` or `"false"`)

**Description:** When set to `"true"`, the director returns additional debugging information in the response, including detailed redirect information stored in the context.

**Example:**

```
X-Pelican-Debug: true
```

**Usage:**

- Typically set when PELICAN_DEBUG environment variable is enabled in the client
- Helps developers and administrators troubleshoot routing and redirection issues

---

### X-Pelican-User

**Direction:** Pelican Server → OA4MP Server (internal)

**Purpose:** Passes authenticated user information to the OA4MP (OAuth for MyProxy) server.

**Format:** Base64-encoded JSON object

**Description:** This is an internal header used when proxying requests from the Pelican server to the OA4MP server. The JSON object contains user authentication information, groups, and allowed scopes.

**JSON Structure:**

```json
{
  "u": "username",
  "g": ["group1", "group2"],
  "s": ["scope1", "scope2"]
}
```

**Example:**

```
X-Pelican-User: eyJ1IjoidXNlcm5hbWUiLCJnIjpbImdyb3VwMSJdLCJzIjpbInNjb3BlMSJdfQ==
```

**Notes:**

- This is a workaround for OA4MP 5.4.x limitations with the device authorization grant
- The header is set/deleted internally and should not be sent by external clients

---

### X-Transfer-Status

**Direction:** Client → Cache/Origin

**Purpose:** Requests that the server send transfer status information in HTTP trailers.

**Format:** Boolean string (`"true"`)

**Description:** When set to `"true"` and the client supports trailers (indicated by `TE: trailers`), the server will include an `X-Transfer-Status` trailer in the response with detailed transfer status information.

**Example:**

```
X-Transfer-Status: true
TE: trailers
```

**Notes:**

- Client must support HTTP trailers
- Used in conjunction with the `TE` header
- Response status is sent in the trailer (see [X-Transfer-Status Trailer](#x-transfer-status-trailer))

---

### X-Pelican-Object-Metadata

**Direction:** Client → Origin (V2 / POSIXv2 origin)

**Purpose:** Attaches uploader-supplied custom metadata to an object on upload, to be forwarded to the origin's configured metadata catalog when object-commit publishing is enabled.

**Format:** A single [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651) Structured-Fields **dictionary**.

**Description:** On a `PUT`, the origin parses this header and inlines its typed key/value pairs into the `object` field of the outbound webhook JSON. Structured Fields are used (rather than embedding JSON in a header) so values keep their type across intermediaries — e.g. `run_number=4172` round-trips as a JSON integer. The reserved keys `path`, `size`, `etag`, and `created_at` are origin-computed and cannot be overridden by the client. The client rejects a custom key that collides with a reserved key before sending the request, and the origin independently ignores (overwrites) any colliding key that still arrives.

**Example:**

```
X-Pelican-Object-Metadata: experiment="atlas", run_number=4172, is_test=?0
```

**Notes:**

- Only meaningful when `Origin.Metadata.Enabled` is true for the export.
- See the [metadata publish design doc](metadata-publish-design.md) for the full webhook contract.

---

## Response Headers

Headers returned by directors, origins, and caches in their responses.

### X-Pelican-Authorization

**Direction:** Director → Client

**Purpose:** Informs the client about token issuers that can provide authorization tokens for the requested resource.

**Format:** Comma-separated list of issuer URLs

**Description:** This header is sent by the director when a request is made for a resource that requires authentication. It lists the issuer(s) that can provide valid tokens for accessing the resource.

**Field Structure:**

```
issuer=<issuer_url>[, issuer=<issuer_url>, ...]
```

**Example:**

```
X-Pelican-Authorization: issuer=https://get-your-tokens.org, issuer=https://get-your-tokens2.org
```

**Usage:**

- Sent only for namespaces that require authentication
- Client can use these issuers to obtain valid access tokens
- Multiple issuers may be listed if the namespace accepts tokens from multiple sources

**CORS:**

- Exposed via `Access-Control-Expose-Headers` for web clients

---

### X-Pelican-Token-Generation

**Direction:** Director → Client

**Purpose:** Provides information about how to generate tokens for the requested resource.

**Format:** Comma-separated key-value pairs

**Description:** This header guides clients on the token generation strategy and parameters needed to obtain access to protected resources.

**Fields:**

- `issuer`: The credential issuer URL
- `base-path`: The base path for which the token should be scoped
- `strategy`: The token generation strategy (e.g., `OAuth2`, `Vault`)
- `max-scope-depth`: Maximum depth for token scopes (integer)

**Example:**

```
X-Pelican-Token-Generation: issuer=https://get-your-tokens.org, base-path=/foo/bar, max-scope-depth=2, strategy=OAuth2
```

**Notes:**

- Only sent for authenticated namespaces
- The `base-path` may be omitted if not available
- A `max-scope-depth` of 0 indicates the header should not be sent

**CORS:**

- Exposed via `Access-Control-Expose-Headers` for web clients

---

### X-Pelican-Namespace

**Direction:** Director → Client

**Purpose:** Provides metadata about the namespace that serves the requested resource.

**Format:** Comma-separated key-value pairs

**Description:** This header contains information about the namespace properties, including whether authentication is required and where to access directory listings.

**Fields:**

- `namespace`: The namespace path (e.g., `/foo/bar`)
- `require-token`: Boolean indicating if token authentication is required (`true` or `false`)
- `collections-url`: (Optional) URL for accessing directory listings/collections

**Example:**

```
X-Pelican-Namespace: namespace=/foo/bar, require-token=true, collections-url=https://my-collections.com
```

**Notes:**

- The `collections-url` is only included if:
  - Both the namespace and origin allow directory listings
  - For authenticated namespaces, the origin has an `AuthURL`
  - For public namespaces, the origin has a regular URL
- Used by clients to determine authentication requirements and discover additional namespace capabilities

**CORS:**

- Exposed via `Access-Control-Expose-Headers` for web clients

---

### X-Pelican-Broker

**Direction:** Director → Client

**Purpose:** Provides the broker URL for the origin serving the requested resource.

**Format:** Single URL string

**Description:** This header contains the broker service URL associated with the origin. The broker is used for connection reversing, allowing origins (or the admin interface of a cache, in the future) to be behind firewalls.

**Example:**

```
X-Pelican-Broker: https://broker.example.com
```

**Notes:**

- Only included if the origin advertises a broker URL
- Typically sent with origin ads (not cache ads)

---

### X-Pelican-JobId (Response)

**Direction:** Director → Client

**Purpose:** Returns the request ID assigned by the director for tracking purposes.

**Format:** UUID string

**Description:** The director generates and returns a unique job ID for each request, which can be used to correlate requests across the system for debugging and monitoring.

**Example:**

```
X-Pelican-JobId: 550e8400-e29b-41d4-a716-446655440000
```

**Notes:**

- Automatically generated by the director if not provided in the request
- Can be used to trace request flow through logs

---

### X-Transfer-Status (Trailer)

**Direction:** Cache/Origin → Client (as HTTP Trailer)

**Purpose:** Provides detailed status information about the file transfer after the response body.

**Format:** HTTP status code followed by status text

**Description:** This trailer is sent at the end of the response body when the client requests it via the `X-Transfer-Status` request header. It indicates whether the transfer completed successfully or encountered errors.

**Format:**

```
<status_code>: <status_text>
```

**Examples:**

```
X-Transfer-Status: 200: OK
X-Transfer-Status: 500: Unable to read test.txt; input/output error
X-Transfer-Status: 500: unexpected EOF
```

**Note:** The format includes a colon and space after the status code, followed by the status text (e.g., "200: OK" or "500: error message").

**Notes:**

- Sent as an HTTP trailer (after the response body)
- Only sent if client sets `X-Transfer-Status: true` and `TE: trailers` headers
- Allows error reporting even after response headers have been sent
- Client must support HTTP trailers to receive this information

---

### X-Pelican-Metadata-Status

**Direction:** Origin → Client (on the upload `PUT` response)

**Purpose:** Tells the uploading client the outcome of the origin's *initial* attempt to publish the object-commit event to the metadata catalog.

**Format:** One of `published`, `queued`, `rejected`.

**Description:** When metadata publishing is enabled, the origin makes one synchronous publish attempt during the `PUT` so the client learns the result immediately:

- `published` — the catalog accepted the event on the first try (nothing left to track).
- `queued` — the first attempt failed transiently; the origin durably queued the event and a background worker will retry (eventual mode only). Accompanied by the query/manage URLs below.
- `rejected` — the catalog permanently refused the event (HTTP 422); it will not be retried. Accompanied by the query/manage URLs so the client can inspect / clean it up.

In transactional mode a failed publish fails the `PUT` itself (5xx), so only `published` is ever reported there.

**Example:**

```
X-Pelican-Metadata-Status: queued
```

---

### X-Pelican-Metadata-Query-Url / X-Pelican-Metadata-Manage-Url

**Direction:** Origin → Client (on the upload `PUT` response, eventual mode)

**Purpose:** Give the uploader unguessable **capability URLs** to check on, and cancel, its own queued publish — without needing a separate bearer token. Possession of the URL is the authorization.

**Format:** Absolute URL.

**Description:** Sent only when the event persists in the queue (`queued` or `rejected`). Each URL embeds a long random per-object token:

- **Query URL** — `GET` returns the current publish state (`pending`/`rejected`, attempt count, last error). Read-only.
- **Manage URL** — `GET` also returns state; `DELETE` cancels/deletes the queued publish. The manage token is required to cancel; the query token cannot.

A `GET` that returns `404` means the token is unknown *or* the publish already completed successfully (successful rows are deleted). Operators can also manage the queue through the admin API (which is gated by the origin admin scope) — these capability URLs are the client-facing equivalent scoped to a single object.

**Example:**

```
X-Pelican-Metadata-Query-Url: https://origin.example.org:8447/api/v1.0/origin_ui/metadata_publish/8Zreal0Random1Token2Here
X-Pelican-Metadata-Manage-Url: https://origin.example.org:8447/api/v1.0/origin_ui/metadata_publish/9OtherRandomManageToken3
```

---

## Metadata Webhook Headers (Origin → External Catalog)

Headers the origin sets on the outbound object-commit webhook `POST` to a configured external metadata catalog.

### X-Pelican-Idempotency-Key

**Direction:** Origin → External Catalog

**Purpose:** Lets the catalog dedupe redelivered events (the origin retries on failure, so the same event may arrive more than once).

**Format:** UUID string (the event's `id`, repeated from the JSON body).

**Description:** Every webhook `POST` carries this header set to the event's stable UUIDv4. Receivers that prefer HTTP-level dedup can key off it without parsing the body; the same value also appears as `id` in the JSON. The non-RFC `Idempotency-Key` name (still an IETF draft) is namespaced with the `X-Pelican-` prefix per project convention.

**Example:**

```
X-Pelican-Idempotency-Key: 8d9d5f3e-4f5b-4f1e-9c1f-2a8a7b1d6c43
```

**Notes:**

- The `POST` is also authenticated with a `Bearer` JWT carrying the `pelican.metadata:/<namespace>` scope (see the [metadata publish design doc](metadata-publish-design.md)).

---

## Other Headers

### X-CSRF-Token

**Direction:** Server → Web Client

**Purpose:** Provides CSRF (Cross-Site Request Forgery) protection for web UI requests.

**Format:** Token string

**Description:** This header contains a CSRF token that must be included in state-modifying requests (POST, PUT, DELETE) to the Pelican web UI. The token is validated server-side to prevent CSRF attacks.

**Notes:**

- Generated using the Gorilla CSRF package
- Shares the same authentication key as the session secret
- Invalid CSRF tokens result in HTTP 403 Forbidden responses
- Missing or invalid authentication tokens result in HTTP 401 Unauthorized responses
- Uses `SameSite=Strict` mode for additional security

---

## Standard Headers Used by Pelican

In addition to custom headers, Pelican also uses standard HTTP headers:

### Authorization

- **Format:** `Bearer <token>`
- **Purpose:** Carries authentication tokens (typically SciTokens or JWTs)
- **Used by:** Clients, directors, origins, caches

### User-Agent

- **Format:** `pelican-<component>/<version>` (e.g., `pelican-client/7.8.0`)
- **Purpose:** Identifies the Pelican component and version making the request
- **Used by:** All Pelican components

### Link

- **Purpose:** Provides metalink-formatted list of redirect servers with priorities
- **Format:** RFC 5988 Web Linking format
- **Used by:** Director responses for client-side load balancing

### Content-Type

- **Purpose:** Standard MIME type header for request/response bodies
- **Common values:** `application/json`, `application/xml`

### Want-Digest / Digest

- **Purpose:** Checksum verification for file transfers
- **Supported algorithms:** CRC32C, MD5
- **Used by:** Clients and servers for data integrity verification

---

## CORS Configuration

The following Pelican headers are configured for CORS (Cross-Origin Resource Sharing) requests:

**Access-Control-Expose-Headers:**

- `X-Pelican-User` (exposed but currently only used internally)
- `X-Pelican-Timeout`
- `X-Pelican-Token-Generation`
- `X-Pelican-Authorization`
- `X-Pelican-Namespace`

**Note:** While `X-Pelican-User` is included in the CORS exposed headers configuration, it is currently only used internally between the Pelican Server and OA4MP Server and is not set by the director in client responses. The CORS configuration may be prepared for future use or is overly permissive.

**Additional Note:** There is a TODO in the codebase to potentially add more headers to `Access-Control-Allow-Headers`:

- Currently allowed: `Content-Type`, `Authorization`, `Depth`
- Potential additions: `X-Pelican-User`, `X-Pelican-Timeout`, `X-Pelican-Token-Generation`, `X-Pelican-Authorization`, `X-Pelican-Namespace`

---

## Header Precedence and Fallbacks

### X-Pelican-Timeout

Can be specified in two ways (in order of precedence):

1. Query parameter: `?pelican.timeout=5s`
1. HTTP header: `X-Pelican-Timeout: 5s`

### X-Pelican-JobId

- If provided by client in request, it is propagated through the system
- If not provided, the director generates a new UUID
- The same job ID is used for all related requests (HEAD, GET, etc.)

---

## Implementation Notes

### Header Parsing

Most Pelican headers use a key-value format that is parsed using the `utils.HeaderParser` function:

```
key1=value1, key2=value2, key3=value3
```

This format is used by:

- `X-Pelican-Namespace`
- `X-Pelican-Token-Generation`

### Canonical Header Keys

When looking up headers from HTTP request objects, Pelican sometimes uses `http.CanonicalHeaderKey()` to ensure proper case handling:

```go
canonicalKey := http.CanonicalHeaderKey("X-Pelican-JobId")
if jobID := ctx.Request.Header[canonicalKey]; len(jobID) > 0 {
    // Use jobID
}
```

### Director Header Generation

The director generates several response headers through dedicated functions:

- `generateXAuthHeader()` - Creates `X-Pelican-Authorization`
- `generateXTokenGenHeader()` - Creates `X-Pelican-Token-Generation`
- `generateXNamespaceHeader()` - Creates `X-Pelican-Namespace`
- `generateXBrokerHeader()` - Creates `X-Pelican-Broker`
- `generateXJobIdHeader()` - Creates `X-Pelican-JobId`

---

## Version History

This documentation is current as of Pelican version 7.x. Header behavior may change in future versions. Check the source code or release notes for the most up-to-date information.

---

## Related Documentation

- [Pelican Architecture](https://docs.pelicanplatform.org/)
- [Token Authentication](https://docs.pelicanplatform.org/)
- [Director API](https://docs.pelicanplatform.org/)

---

## Contributing

If you find any inaccuracies in this documentation or notice new headers that should be documented, please open an issue or pull request on the [Pelican GitHub repository](https://github.com/PelicanPlatform/pelican).
