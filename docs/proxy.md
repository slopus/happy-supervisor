# happy-supervisor command proxies

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

## One proxy per command

Every exec whose policy has `network.mode: "isolated"` (policy.md, Network), and every exec with a
`proxy`, gets its own **command proxy**: one HTTP proxy and one SOCKS5 proxy, run by the node
outside any sandbox, alive until the command exits. A raw or host-mode exec with no `proxy` gets
none.

For each outbound request the command proxy decides, in order:

1. **Credential route.** The host matches `proxy.hosts` and the request came through the HTTP
   proxy: it goes to the control plane over the link (How requests travel). In isolated mode the
   host must also pass `egress`, or the request is refused; `ports` does not apply, since the
   control plane decides where the request goes. Through SOCKS5 a credential host is refused,
   since the node can only rewrite HTTP.
2. **Egress check**, isolated mode only. The host must pass `network.egress` and the port must be
   in `network.ports`.
3. **Resolve and connect.** The proxy resolves the name itself. In isolated mode it drops every
   address that is loopback, private (RFC 1918, ULA), link-local, CGNAT (100.64/10), Azure's 168.63.129.16, multicast,
   unspecified or one of the node's own, unless `egress.allow` names that literal IP. It tries
   the remaining addresses in order and uses the first that accepts.
4. **Tunnel.** HTTP `CONNECT` and SOCKS5 `CONNECT` splice bytes; absolute-form `http://` requests
   are forwarded with hop-by-hop headers removed. Only the credential route terminates TLS.

A refusal is HTTP `403` with a one-line reason, or SOCKS5 reply `0x02`. SOCKS5 offers no
authentication (`0x00`), `CONNECT` only (`UDP ASSOCIATE` and `BIND` get `0x07`), and address types
domain, IPv4 and IPv6. The HTTP proxy takes `CONNECT` and absolute-form `http://` requests; other
forms get `400`.

Every refusal sends a `net.denied` event (api.md), at most 20 a second per exec; the rest are
counted in the next event's `dropped`:

```json
{ "kind": "net.denied", "body": { "execId": "e_1", "host": "evil.example", "port": 443, "via": "http", "reason": "egress" } }
```

`reason` is `egress`, `port`, `address` (every resolved address was filtered), `resolve` (no
address) or `credential` (a credential host through SOCKS5). `via` is `http` or `socks5`. In host
mode a name that does not resolve is not a policy decision: the client gets HTTP `502` or SOCKS5
reply `0x04`, and no event is sent.

## What the command gets

| Platform | The proxy listens on | The command reaches it at |
|---|---|---|
| Linux, isolated | `http.sock` and `socks.sock` in `private/net/<n>/` of the state directory, bind-mounted into the sandbox | `127.0.0.1:3128` (HTTP) and `127.0.0.1:1080` (SOCKS5) in the sandbox's own network namespace, where the sandbox helper bridges each to its socket |
| Otherwise | `127.0.0.1:<ephemeral>` each | the same addresses |

A Unix socket's path holds at most 107 bytes. If the state directory is too deep for that, an
isolated exec on Linux fails with `sandbox_unavailable`.

The node **sets** these variables, replacing any the control plane passed:

| Variable | Value |
|---|---|
| `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` | `http://<http-addr>`, or `http://happy:<secret>@<http-addr>` with a credential route on a TCP port |
| `ALL_PROXY`, `all_proxy` | `socks5h://<socks-addr>`, isolated mode only |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1,::1` |
| `GIT_SSH_COMMAND` | `ssh -o ProxyCommand='<supervisor> __connect %h %p'`, isolated mode only |
| `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO` | the node's CA bundle path, with a credential route |

`<secret>` is 32 random bytes, base64url, fresh for each command. A connection to the HTTP proxy
without it gets `407`. Any local process can reach a TCP port, so a credential route there needs
the secret; on a Unix socket only the sandbox reaches the proxy, and there is none. Without a
credential route the proxy grants nothing a local process could not do itself.

Programs that ignore the proxy variables have no network in isolated mode, and bypass the proxy
in host mode, where it catches traffic but is not a network boundary.

### The node's CA

At first start the node creates its own certificate authority, an ECDSA P-256 key and a
self-signed CA certificate valid for 10 years, with a name constraint-free basic CA profile. The
key lives in the private part of the state directory (never readable by sandboxed commands). At
every start the node writes `public/ca-bundle.pem` in the state directory: the platform's trusted
roots followed by the node's CA certificate. Sandboxed commands with a `proxy` may read exactly
that file, as if their policy granted it.

For each intercepted host the node mints a leaf certificate signed by its CA: the host as its
only DNS name, server authentication only, valid for 30 days. Leaves live only in memory. The
node keeps the 256 most recently used and mints a new one when a cached leaf is a week old.

## How requests travel

The proxy handles three kinds of client requests:

| Client sends | Host in `hosts` | Host not in `hosts` |
|---|---|---|
| `CONNECT host:port` (HTTPS) | The node answers `200`, then terminates TLS itself with a certificate for `host` signed by its CA (ALPN `http/1.1`). Each HTTP/1.1 request inside is forwarded through the control plane with `scheme: "https"`. | An opaque TCP tunnel to `host:port`, after the checks above. |
| `GET http://host/…` (plain HTTP) | Forwarded through the control plane with `scheme: "http"`. | Forwarded by the node, after the checks above. |
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
`trailer`, `transfer-encoding`, `upgrade`, and any header named in `connection`. It also removes
`expect` from requests, since it answers `100 Continue` to the client itself. Body framing is
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
* At most 32 MiB of request body, summed over every stream of the node (tunnels included,
  tunnels.md), may be sent and not yet credited. Past that every request body pauses until
  credit arrives. Each `proxy.body` waits in
  the link's queue of messages it must not drop until it is acknowledged, and that queue ends
  the session at 64 MiB (api.md, Lost sessions), so 1024 full windows could not fit.
* When the session is lost (api.md, Lost sessions), every open stream ends. A client still
  waiting for a response head gets `502`. A client in the middle of a response sees its
  connection closed.
* `proxy.reset` from the control plane before a response head gives the client `502`, after
  one closes the client connection.
* A control plane that breaks the stream rules resets the stream: a `proxy.body` over 64 KiB, or
  past the window, or before `proxy.response`; a second `proxy.response`; `proxy.end` before
  `proxy.response`; or a response head the node cannot use (an informational `1xx` status, or an
  invalid header). The node sends `proxy.reset` and the client gets `502` before a response head
  or sees its connection closed after one. Messages for a stream the node no longer has are
  ignored.
* A control plane that does not support proxying answers the first `proxy.request` of any stream
  with `proxy.reset`, and the client gets `502`.
* When the command exits, its proxy stops, and its open streams are reset.
