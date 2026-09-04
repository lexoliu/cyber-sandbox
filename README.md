# cyber-sandbox

Isolated, fully audited security-research environments on macOS.

Each session is one lightweight virtual machine started through
[`apple/container`](https://github.com/apple/container). Inside it: a Kali headless
toolchain for analysing samples. Outside it: your credentials, which never cross the
boundary.

You never start, stop, list or delete a machine. You open a session; the machine under it
is created when you need one, resumed when you come back to it, and reclaimed once it has
gone a week untouched or the host runs short of disk.

## What it guarantees

**No credential ever enters the sandbox.** Nothing inside a session holds a token, so a
sample that reads every file it can reach still finds none.

**No packet leaves unaudited.** Traffic is redirected by uid to an in-guest gateway that
terminates TLS with its own authority and records every DNS question, connection, TLS
handshake and HTTP exchange as JSONL. Anything the gateway cannot audit — QUIC above all
— is dropped by the packet filter rather than passed. The policy is installed by the init
process before anything else runs, and `CAP_NET_ADMIN` is removed from the bounding set
afterwards, so code inside the sandbox cannot change it even as root. If the gateway
dies, the redirect target stops listening and egress fails closed.

## Use

```sh
cyber-sandbox shell  --samples ~/samples  # a new session, with samples mounted read-only
cyber-sandbox claude --samples ~/samples  # the same, with Claude Code driving it
cyber-sandbox codex  --samples ~/samples  # or Codex
cyber-sandbox audit c0ffee                # follow every packet that session sends
cyber-sandbox shell --resume              # pick a session to come back to
cyber-sandbox claude --resume c0ffee      # or name it
```

The first run builds the Kali image with the gateway compiled into it, from the checkout
you run it in. Every run after that starts in seconds.

`--arch amd64` runs an x86_64 root filesystem under Rosetta, for samples that are not
arm64. It is settled when the session is created, so an `amd64` sample gets its own
session rather than a flag on an existing one.

## Agents

`cyber-sandbox claude` and `cyber-sandbox codex` open a session and hand it to an agent
running with approvals off: the session is the sandbox, so an agent that stops to ask for
permission to read a file is one you have to babysit for no gain.

Both keep your subscription. Neither is given anything that could be used to log in as
you after the run.

### Claude Code

Claude Code runs inside the session, because that is where the sample is. What stays on
the host is the login: cyber-sandbox reads the access token out of your Keychain, serves
it over a unix socket, and forwards that socket into the session over ssh. Inside, a
courier fetches the token, writes it where Claude Code looks for a host-managed
credential, starts Claude Code, and fetches again every five minutes so a token renewed on
the host reaches the session without the session ever holding what renews it.

The refresh token never crosses. What the session gets is the access token, which expires
in hours on its own, is readable only by the account the agent runs as, and is taken off
the disk when the agent exits. Even a copy taken while the agent ran is inert afterwards:
Claude Code checks that the process the credential names is still alive and was started
when the file says it was.

Your own `claude` is untouched — the Keychain item is read, never rewritten, so nothing
here can make you log in again.

### Codex

Codex itself never leaves the host. Your ChatGPT subscription, and the credential behind
it, stay where they already are; what runs in the session is `codex exec-server`, which
authenticates to nothing.

Three things in your configuration are borrowed for the length of a run and handed back
exactly as they were: the session becomes an entry in `~/.codex/environments.toml`, it is
preselected there so Codex opens on it without a menu, and the directory it works in is
marked trusted in `~/.codex/config.toml` so opening it does not begin with a question
about a directory cyber-sandbox made seconds earlier.

That directory is `~/.cyber-sandbox/work/<id>`, and on the host it stays empty. Codex
resolves the directory it works in against the host and then asks the session to execute
there, so the path has to exist on both sides — inside the session the same path is a
symlink to `/work`. Nothing is mounted through it, and a session left holding a path the
host does not have is one where Codex quietly runs the command on your laptop instead.

## Layout

| Crate | Role |
|---|---|
| `cyber-sandbox` | The CLI |
| `cyber-sandbox-runtime` | Typed driver for the `container` CLI |
| `cyber-sandbox-image` | Renders the Dockerfile, entrypoint and egress policy |
| `cyber-sandbox-gateway` | The in-guest auditing proxy (Linux only) |
| `cyber-sandbox-courier` | Holds an agent's borrowed credential in-guest (Linux only) |
| `cyber-sandbox-creds` | The borrowed credential's wire and on-disk formats |
| `cyber-sandbox-audit` | Audit record schema and JSONL reader/writer |
| `cyber-sandbox-agents` | Reads the host's logins and registers a session with Codex |

## Requirements

macOS 26 on Apple silicon, and `brew install container`.

## License

Apache-2.0
