# happy-supervisor credential proxy

A command can send its HTTP traffic for chosen hosts **through the control plane**. The node
catches those requests, even over HTTPS, and hands them to the control plane over the link. The
control plane decides where each request really goes, adds credentials there, and streams the
response back. Credentials never reach the machine. A command can call `api.github.com` with no
token in its environment and still be authenticated, because the control plane injects the token
on its side.

Each such command carries an opaque **proxy token**. The node never interprets it. It attaches the
token to every request it forwards, and the control plane uses it to find the command's
configuration: which upstream, which credential, what to allow.

## Asking for it

`exec.start` takes an optional `proxy`:

```json
"proxy": { "token": "pt_8f1c…", "hosts": ["api.github.com", "*.openai.com", "registry.npmjs.org"] }
```

* `token` is opaque, 1 to 4096 bytes of UTF-8. It is never logged and never put in the command's
  environment.
* `hosts` lists the hosts to send through the control plane. An entry is an exact DNS name, or
  `*.` and a suffix, which matches every name under that suffix but not the suffix itself.
  Matching ignores case and a trailing dot. IP addresses are not allowed as entries. At most 256
  entries.

Raw and sandboxed commands can both use a proxy.

## What the command gets

The node starts one proxy for the command, an HTTP proxy on a loopback port that only that
command knows the password to. It **sets** these variables in the command's environment,
replacing any the control plane passed:

| Variable | Value |
|---|---|
| `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` | `http://happy:<secret>@127.0.0.1:<port>` |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO` | the node's CA bundle path |

`<secret>` is 32 random bytes, base64url, fresh for each command. A connection to the proxy
without it gets `407`. The proxy stops when the command exits.

Programs that ignore proxy variables bypass the proxy. Their traffic goes out directly, like any
outbound connection (policy.md, Outbound network). The proxy catches traffic. It is not a
network boundary.

### The node's CA

At first start the node creates its own certificate authority, an ECDSA P-256 key and a
self-signed CA certificate valid for 10 years, with a name constraint-free basic CA profile. The
key lives in the private part of the state directory (never readable by sandboxed commands). At
every start the node writes `public/ca-bundle.pem` in the state directory: the platform's trusted
roots followed by the node's CA certificate. Sandboxed commands with a `proxy` may read exactly
that file, as if their policy granted it.

## How requests travel

The proxy handles three kinds of client requests:

| Client sends | Host in `hosts` | Host not in `hosts` |
|---|---|---|
| `CONNECT host:port` (HTTPS) | The node answers `200`, then terminates TLS itself with a certificate for `host` signed by its CA (ALPN `http/1.1`). Each HTTP/1.1 request inside is forwarded through the control plane with `scheme: "https"`. | An opaque TCP tunnel straight to `host:port`. |
| `GET http://host/…` (plain HTTP) | Forwarded through the control plane with `scheme: "http"`. | Forwarded directly by the node. |
| A WebSocket or other `Upgrade` request | `501`. Not supported in this version. | Tunnelled directly. |

The node never connects to a listed host itself. The control plane can send a request anywhere,
including to a different host than the one the command named.

### Link messages

Forwarded requests are **streams** on the link: ordered, confirmed messages (api.md, Link
protocol) in both directions, keyed by a `streamId`, a UUIDv7 the node chooses. They are events,
so they get no `reply`. None of them is ever dropped.

Node to control plane:

```json
{ "kind": "proxy.request", "body": { "streamId": "0193…", "execId": "build-1", "token": "pt_8f1c…",
  "method": "POST", "scheme": "https", "host": "api.openai.com", "port": 443, "path": "/v1/responses",
  "headers": [["content-type", "application/json"], ["user-agent", "curl/8.9"]] } }
```

Control plane to node:

```json
{ "kind": "proxy.response", "body": { "streamId": "0193…", "status": 200,
  "headers": [["content-type", "text/event-stream"]] } }
```

Both directions:

* `proxy.body { streamId, data }`. A piece of the request or response body, at most 64 KiB.
* `proxy.end { streamId }`. The sender's body is complete.
* `proxy.reset { streamId, reason }`. The stream is abandoned in both directions. `reason` is a
  short text for logs.
* `proxy.credit { streamId, bytes }`. Flow control (below).

`headers` is a list of `[name, value]` pairs in order, names lowercase, values bytes. Repeated
headers stay repeated. The node removes hop-by-hop headers before forwarding and after receiving:
`connection`, `keep-alive`, `proxy-authorization`, `proxy-authenticate`, `proxy-connection`, `te`,
`trailer`, `transfer-encoding`, `upgrade`, and any header named in `connection`. Body framing is
the stream itself. The node de-chunks request bodies, and frames responses to the client with
`content-length` when the control plane sent one, or chunked encoding otherwise.

A request stream is complete when the node has sent `proxy.end`. A response is complete when the
control plane has sent `proxy.response` and then `proxy.end`. The control plane may send the
response before the request body is complete. Server-sent events and other long responses
stream through as `proxy.body` pieces arrive.

### Flow control

Each direction of each stream starts with a **window** of 1 MiB. A sender may have at most the
window's worth of `proxy.body` bytes that the receiver has not yet credited. The receiver sends
`proxy.credit` with the number of bytes it has passed on (to the client, or upstream), and the
sender's window grows by that much. A sender whose window is empty stops reading from its source
until credit arrives. So one slow client or upstream never fills the link's queue.

### Limits and failure

* At most 64 open streams per command and 1024 per node. Past that the client gets `503`.
* When the session is lost (api.md, Lost sessions), every open stream ends. A client still
  waiting for a response head gets `502`. A client in the middle of a response sees its
  connection closed.
* `proxy.reset` from the control plane before a response head gives the client `502`, after
  one closes the client connection.
* A control plane that does not support proxying answers the first `proxy.request` of any stream
  with `proxy.reset`, and the client gets `502`.
* When the command exits, its proxy stops, and its open streams are reset.
