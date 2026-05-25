# tests/fixtures/hooks-cursor/

Cursor 1.7+ hook adapter fixtures (M7 / ADR 0014). Each subdirectory
holds one synthetic Cursor hook payload as `input.json`, plus optional
`allow.toml` for allowlist-override cases.

| Fixture                | Event / Path                              | Expected decision |
|------------------------|-------------------------------------------|-------------------|
| `deny-ssh-read/`       | `beforeReadFile ~/.ssh/id_rsa`            | deny (hooks.credential-file-read) |
| `deny-bash-cat-env/`   | `beforeShellExecution cat .env`           | deny (hooks.credential-shell-read) |
| `deny-pipe-network/`   | `beforeShellExecution curl ... creds`     | deny (hooks.credential-pipe-network) |
| `allow-public-pub/`    | `beforeReadFile ~/.ssh/id_ed25519.pub`    | allow (public-half carve-out)      |
| `allow-benign-read/`   | `beforeReadFile /tmp/README.md`           | allow                              |
| `allow-with-override/` | `beforeReadFile ~/.aws/credentials` + allowlist | allow (entry in allow.toml)  |

Fixtures parallel the M6 `tests/fixtures/hooks-claude/` set: every
malicious Claude fixture has a Cursor-shaped equivalent producing the
same rule ID. The cross-vendor parity test in
`packages/hooks-cursor/tests/interceptor.test.ts` enforces this.

Fixtures are JSON, so they are not subject to ADR 0010's markdown
marker syntax. They are also not loaded by the scanner — `warden scan`
does not interpret JSON in this directory as anything but content.
