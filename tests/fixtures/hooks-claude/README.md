# tests/fixtures/hooks-claude/

PreToolUse hook adapter fixtures (M6 / ADR 0013). Each subdirectory
holds one synthetic Claude Code tool-call payload as `input.json`,
plus optional `allow.toml` for allowlist-override cases.

| Fixture                | Tool / Path                          | Expected decision |
|------------------------|--------------------------------------|-------------------|
| `deny-ssh-read/`       | `Read ~/.ssh/id_rsa`                 | deny (hooks.credential-file-read) |
| `deny-bash-cat-env/`   | `Bash cat .env`                      | deny (hooks.credential-shell-read) |
| `deny-pipe-network/`   | `Bash curl ... ~/.aws/credentials`   | deny (hooks.credential-pipe-network) |
| `allow-public-pub/`    | `Read ~/.ssh/id_ed25519.pub`         | allow (public-half carve-out)      |
| `allow-benign-read/`   | `Read README.md`                     | allow                              |
| `allow-with-override/` | `Read ~/.aws/credentials` + allowlist | allow (entry in allow.toml)       |

Fixtures are JSON, so they are not subject to ADR 0010's markdown
marker syntax. They are also not loaded by the scanner — `warden scan`
does not interpret JSON in this directory as anything but content.
