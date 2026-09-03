# cyber-sandbox

Isolated, fully audited security-research environments on macOS.

Each sandbox is one lightweight virtual machine started through
[`apple/container`](https://github.com/apple/container). Inside it: a Kali headless
toolchain for analysing samples. Outside it: your credentials, which never cross the
boundary.

## What it guarantees

**No credential ever enters the sandbox.** Claude Code and Codex both keep their model
side — and their tokens — on the host, and run only their tool side inside the sandbox
over SSH. The sandbox needs no egress at all to be usable as a research environment, and
holds nothing worth stealing.

**No packet leaves unaudited.** Traffic is redirected by uid to an in-guest gateway that
terminates TLS with its own authority and records every DNS question, connection, TLS
handshake and HTTP exchange as JSONL. Anything the gateway cannot audit — QUIC above all
— is dropped by the packet filter rather than passed. The policy is installed by the init
process before anything else runs, and `CAP_NET_ADMIN` is removed from the bounding set
afterwards, so code inside the sandbox cannot change it even as root. If the gateway
dies, the redirect target stops listening and egress fails closed.

Model-API traffic is deliberately outside this trail: it never traverses the sandbox's
network stack in the first place, travelling instead over the agents' SSH channel to the
host. What the audit records is everything the *sample* and the agents' *tools* do.

## Use

```sh
cyber-sandbox doctor --fix          # check the host, start the runtime
cyber-sandbox image build           # build the Kali + gateway image
cyber-sandbox up lab --samples ~/samples
cyber-sandbox shell lab             # a shell in the sandbox
codex                               # /environment, then pick lab
cyber-sandbox audit tail lab -f     # watch every packet it sends
cyber-sandbox rm lab
```

`--arch amd64` runs an x86_64 root filesystem under Rosetta, for samples that are not
arm64.

## Layout

| Crate | Role |
|---|---|
| `cyber-sandbox` | The CLI |
| `cyber-sandbox-runtime` | Typed driver for the `container` CLI |
| `cyber-sandbox-image` | Renders the Dockerfile, entrypoint and egress policy |
| `cyber-sandbox-gateway` | The in-guest auditing proxy (Linux only) |
| `cyber-sandbox-audit` | Audit record schema and JSONL reader/writer |
| `cyber-sandbox-agents` | Registers a sandbox with Claude Code and Codex |

## Requirements

macOS 26 on Apple silicon, and `brew install container`.

## License

Apache-2.0
