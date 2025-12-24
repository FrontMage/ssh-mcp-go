# ssh-mcp-go

MCP server for SSH operations built with:
- https://github.com/mark3labs/mcp-go
- https://github.com/melbahja/goph

It exposes three tools over stdio:
- `ssh_exec`: run a remote command and return output
- `ssh_upload`: upload a local file or directory to remote
- `ssh_download`: download a remote file or directory to local
- `ssh_exec_dynamic`: run a remote command with per-call SSH parameters

## Requirements

- Go 1.20+ (recommended)
- An SSH server you can reach

## Environment Variables

- `SSH_SERVER` (required): `user@host` or `host`
- `SSH_PORT` (optional, default 22)
- `SSH_KEY` (optional): path to private key
- `SSH_PASSPHRASE` or `SSH_KEY_PASSPHRASE` (optional): private key passphrase
- `SSH_PASSWORD` (optional): password auth (also used for keyboard-interactive)
- `SSH_USER` (optional): username when `SSH_SERVER` does not include `user@`

Auth priority is simple: if `SSH_KEY` is set, its key auth is included; if
`SSH_PASSWORD` is set, password auth is included. At least one must be provided.

## Build

```bash
go build -o ssh-mcp-go .
```

## Run (stdio)

```bash
SSH_SERVER=user@host \
SSH_PORT=22 \
SSH_KEY=~/.ssh/id_rsa \
SSH_PASSPHRASE=your_passphrase \
./ssh-mcp-go
```

## Tool Usage (example)

From an MCP client, call tools with the following arguments:

- `ssh_exec`
  - `command` (string)
- `ssh_upload`
  - `local_path` (string)
  - `remote_path` (string)
- `ssh_download`
  - `remote_path` (string)
  - `local_path` (string)
- `ssh_exec_dynamic`
  - `server` (string, host or user@host)
  - `user` (string, required if server has no user@)
  - `port` (int, optional)
  - `password` (string, optional)
  - `key_path` (string, optional)
  - `passphrase` (string, optional)
  - `command` (string)

## Notes

- Host key verification is not enforced (uses `InsecureIgnoreHostKey`).
- Directory transfers are recursive.
