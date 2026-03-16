# envcrypt

Currently, no coding agent related editor seems to have an iron-clad way to prevent .env variables from being accidentally read by an AI agent, whether directly or indirectly via an invoked tool. This lightweight bash tool prevents casual .env exposure from AI agents, as well as accidental `cat`, or screen-sharing exposure. It works by encrypting .env values, then as needed, decrypting them for a selected time duration (1 min, 2 min, 5 min), at which point they are automatically encrypted again (including on early exit via `CTRL+c`)

Keys are always stored as plaintext. Only values are encrypted, wrapped in an `ENC(...)` sentinel so they remain easy to identify.

This does not replace a proper secrets manager.

Encryption uses AES-256-CBC with PBKDF2 key derivation via OpenSSL. 

## Example

**First run** — no `.envcrypt` file exists yet, so you're walked through setup:

```
$ ./envcrypt.sh
No projects configured. Let's set one up.
─────────────────────────────────────────────────────

  Project name: project-one
  Path to .env (absolute, or relative to the envcrypt directory): ../project-one/.env

✓ Project "project-one" saved as default.
  Stored path: /your/project-one/.env
```

**Subsequent runs** — project menu appears:

```
$ ./envcrypt.sh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Select project:

  1) * project-one  [default]
        /your/project-one/.env
  2)   project-two
        /your/project-two/.env

  a) Add a new project
  d) Change default
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Choice [ENTER for default]:
```

**Encrypt mode** — triggered when no `ENC(...)` values are detected:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Mode:        encrypt  (no encrypted values detected)
  Project:     project-one
  Target file: /your/project-one/.env
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Enter encryption password:
Confirm encryption password:

✓ Encryption complete.
  File:             /your/project-one/.env
  Values encrypted: 3
```

The `.env` file now looks like:

```
DATABASE_URL=ENC(U2FsdGVkX1+8Lg3bkBCZ...)
API_KEY=ENC(U2FsdGVkX1+mXq9z3KpA...)
EMPTY_VAR=
```

**Unlock mode** — triggered when `ENC(...)` values are detected:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Mode:        unlock  (encrypted values detected)
  Project:     project-one
  Target file: /your/project-one/.env
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Select decryption duration:
  1) 1 minute
  2) 2 minutes
  3) 5 minutes

Choice [1/2/3]: 1

Enter decryption password:

✓ Decrypted: /your/project-one/.env
  Values will be re-encrypted in 1 minute.
  Press Ctrl+C to re-encrypt and exit early.

  Re-encrypting in 60 seconds...
  Re-encrypting in 30 seconds...

Duration expired. Re-encrypting /your/project-one/.env...
✓ Re-encrypted: /your/project-one/.env
  Goodbye.
```

## Requirements

- Bash 4.0+ (see below — macOS ships with bash 3.2)
- OpenSSL (available by default on macOS and most Linux distros)

### Installing bash 4+

**macOS** ships with bash 3.2 due to licensing. Install a modern version via Homebrew:

```sh
brew install bash
```

Then add it to the front of your `PATH` so `env bash` resolves to it:

```sh
# Apple Silicon
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc

# Intel
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc
```

**Linux** distros typically ship a recent bash, but if yours is outdated:

```sh
# Debian / Ubuntu
sudo apt install bash

# Fedora / RHEL
sudo dnf install bash

# Arch
sudo pacman -S bash
```

The script will tell you if your bash is too old:

```
✗ bash 4.0+ is required (current: 3.2.57(1)-release)
  Install it with: brew install bash
```

## Usage

Make the script executable once:

```sh
chmod +x envcrypt.sh
```

Then run it directly:

```sh
./envcrypt.sh
```

Alternatively, without changing permissions:

```sh
bash envcrypt.sh
```

> **Important:** Do **not** source it with `. ./envcrypt.sh` or `source ./envcrypt.sh`. Sourcing runs the script inside your current shell session, which means any `exit` call will close your terminal. The script will refuse to run if it detects it is being sourced.

That's it. The script auto-detects what to do based on the state of your `.env` file:

| File state | Operation |
|---|---|
| Any value wrapped in `ENC(...)` | **Unlock** — decrypt temporarily, then re-encrypt |
| No `ENC(...)` values found | **Encrypt** — encrypt all plaintext values |

## Encrypt mode

When no `ENC(...)` values are detected, the script encrypts all plaintext values:

1. Prompts for a password (with confirmation)
2. Encrypts every non-empty, non-comment value in-place
3. Already-encrypted values are skipped (idempotent)

**Before Encryption:**
```
DATABASE_URL=postgres://user:password@localhost/mydb
API_KEY=sk-abc123
EMPTY_VAR=
```

**After Encryption:**
```
DATABASE_URL=ENC(U2FsdGVkX1+...)
API_KEY=ENC(U2FsdGVkX1+...)
EMPTY_VAR=
```

## Unlock mode

When `ENC(...)` values are detected, the script temporarily decrypts them:

1. Prompts for a decryption duration (1, 2, or 5 minutes)
2. Prompts for the password (up to 4 attempts, verified against the first encrypted value before touching the file)
3. Decrypts all values in-place
4. Counts down and automatically re-encrypts when the duration expires
5. **Ctrl+C** re-encrypts immediately and exits

> **Note:** If the script is killed with `SIGKILL` (`kill -9`) during the unlock window, it cannot re-encrypt. Run `./envcrypt.sh` again to re-encrypt the file.

## The `.envcrypt` dotfile

Projects are stored in `.envcrypt`, next to `envcrypt.sh`, in `NAME=path` format. The `*` prefix marks the default:
  1) * project-one  [default]
  /your/project-one/.env
  2)   project-two
        /your/project-two/.env
```
*project-one=/your/project-one/.env
project-two=/your/project-two/.env
```

Entries can be edited manually at any time. Rules:
- One entry per line
- Exactly one `*` prefix for the default (the script manages this automatically via the `d` menu option)
- Blank lines and `#` comments are ignored
- Paths can be absolute or relative to the `envcrypt` directory (where `envcrypt.sh` lives)

`.envcrypt` is listed in `.gitignore` since it contains machine-local absolute paths.

## Security notes

- Encryption uses **AES-256-CBC** with **PBKDF2** key derivation (100,000 iterations)
- The password is never written to disk
- File writes are atomic (written to a temp file, then moved) to avoid partial states
- This is **not** a substitute for a proper secrets manager (Vault, AWS Secrets Manager, 1Password, etc.)
- Anyone with access to both the `.env` file and the password can decrypt it
