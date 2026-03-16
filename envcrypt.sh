#!/usr/bin/env bash
# Requires bash 4.0+.
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "✗ bash 4.0+ is required (current: $BASH_VERSION)" >&2
  case "$(uname -s)" in
    Darwin) echo "  Install it with: brew install bash" >&2 ;;
    Linux)  echo "  Install it with your package manager, e.g.: sudo apt install bash" >&2 ;;
    *)      echo "  Please install bash 4.0+ for your platform." >&2 ;;
  esac
  exit 1
fi

# Must be executed, not sourced. Sourcing would cause 'exit' calls to close
# your terminal session and trap/signal behaviour would be unpredictable.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  echo "✗ Do not source this script. Run it directly:" >&2
  echo "    ./envcrypt.sh" >&2
  return 1
fi
set -euo pipefail

# =============================================================================
# envcrypt.sh
#
# A unified tool for encrypting and decrypting .env file values using
# AES-256-CBC with PBKDF2 key derivation via OpenSSL. Keys remain plaintext;
# only values are encrypted and wrapped in an ENC(...) sentinel.
#
# The script auto-detects the operation based on the state of the target file:
#   - If any value is wrapped in ENC(...), the file is considered encrypted
#     and the script will unlock (decrypt) it temporarily, then re-encrypt.
#   - Otherwise, the script will encrypt all plaintext values.
#
# Usage:
#   ./envcrypt.sh
#
# On first run, you will be prompted for a project name and .env path.
# These are stored in .envcrypt (next to this script) for future runs.
# Multiple projects are supported; see .envcrypt for the format:
#
#   *project-one=/your/project-one-v1/.env
#   project-two=/your/project-two/.env
#
# The * prefix marks the default project.
#
# Security note:
#   This is a lightweight protection layer to prevent casual exposure of .env
#   values (e.g., AI agents reading the file, screen-sharing, accidental cat).
#   It is NOT a substitute for a proper secrets manager.
#
#   If the script is killed with SIGKILL (kill -9) during unlock, it cannot
#   re-encrypt. Run envcrypt.sh again manually to re-encrypt the file.
# =============================================================================

ENCRYPTION_CIPHER="aes-256-cbc"
PBKDF2_ITERATIONS=100000
MAX_PASSWORD_ATTEMPTS=4

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
DOTFILE="${SCRIPT_DIR}/.envcrypt"

# -----------------------------------------------------------------------------
# Terminal safety and input helpers
#
# Even on bash 5, SIGINT is queued during a blocking `read` and only delivered
# after read returns — meaning a trap cannot fire until the user presses Enter.
# The fix is `read -t 0.1 -n 1`: read one character at a time with a short
# timeout. Each timeout is a point where pending signals are delivered, so
# Ctrl+C is responded to within ~0.1s without requiring Enter.
#
# read_line   — visible input (plain text)
# read_password — hidden input (no echo)
# Both exit cleanly on Ctrl+C or Ctrl+D.
# -----------------------------------------------------------------------------

_on_exit() {
  stty echo 2>/dev/null || true
}
trap '_on_exit' EXIT

_on_sigint() {
  echo ""
  exit 0
}
trap '_on_sigint' SIGINT SIGTERM

# read_line "Prompt text" varname
read_line() {
  local _prompt="$1"
  local _varname="$2"
  local _buf="" _char="" _in_escape=0
  printf "%s" "$_prompt"
  while true; do
    if IFS= read -r -s -n 1 -t 0.1 _char 2>/dev/null; then
      # Start of an ANSI escape sequence (arrow keys, function keys, etc).
      # Consume all following bytes until we see the terminating letter,
      # which is any byte in the range A-Z or a-z (or ~ for some sequences).
      if [[ "$_char" == $'\e' ]]; then
        _in_escape=1
        continue
      fi
      if [[ $_in_escape -eq 1 ]]; then
        # Keep consuming until we hit the final byte of the sequence
        if [[ "$_char" =~ [A-Za-z~] ]]; then
          _in_escape=0
        fi
        continue
      fi
      if [[ -z "$_char" || "$_char" == $'\r' ]]; then
        # Enter pressed (empty string on LF, \r on CR)
        echo ""
        break
      elif [[ "$_char" == $'\177' || "$_char" == $'\b' ]]; then
        # Backspace
        if [[ -n "$_buf" ]]; then
          _buf="${_buf%?}"
          printf '\b \b'
        fi
      elif [[ "$_char" < $'\x20' ]]; then
        # Discard other non-printable control characters
        true
      else
        _buf+="$_char"
        printf "%s" "$_char"
      fi
    fi
    # On timeout, loop — pending signals are delivered here
  done
  printf -v "$_varname" '%s' "$_buf"
}

# read_password "Prompt text" varname
read_password() {
  local _prompt="$1"
  local _varname="$2"
  local _buf="" _char="" _in_escape=0
  printf "%s" "$_prompt"
  stty -echo 2>/dev/null || true
  while true; do
    if IFS= read -r -s -n 1 -t 0.1 _char 2>/dev/null; then
      if [[ "$_char" == $'\e' ]]; then
        _in_escape=1
        continue
      fi
      if [[ $_in_escape -eq 1 ]]; then
        if [[ "$_char" =~ [A-Za-z~] ]]; then
          _in_escape=0
        fi
        continue
      fi
      if [[ -z "$_char" || "$_char" == $'\r' ]]; then
        echo ""
        break
      elif [[ "$_char" == $'\177' || "$_char" == $'\b' ]]; then
        if [[ -n "$_buf" ]]; then
          _buf="${_buf%?}"
        fi
      elif [[ "$_char" < $'\x20' ]]; then
        true
      else
        _buf+="$_char"
      fi
    fi
  done
  stty echo 2>/dev/null || true
  printf -v "$_varname" '%s' "$_buf"
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

print_error() {
  echo "✗ $1" >&2
}

print_success() {
  echo "✓ $1"
}

encrypt_value() {
  local plaintext="$1"
  local password="$2"
  echo -n "$plaintext" | openssl enc -"$ENCRYPTION_CIPHER" -pbkdf2 -iter "$PBKDF2_ITERATIONS" -a -A -pass pass:"$password" 2>/dev/null
}

decrypt_value() {
  local ciphertext="$1"
  local password="$2"
  echo -n "$ciphertext" | openssl enc -d -"$ENCRYPTION_CIPHER" -pbkdf2 -iter "$PBKDF2_ITERATIONS" -a -A -pass pass:"$password" 2>/dev/null
}

encrypt_file() {
  local file="$1"
  local password="$2"
  local temp_file
  temp_file=$(mktemp)

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" ]]; then
      echo "" >> "$temp_file"; continue
    fi
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
      echo "$line" >> "$temp_file"; continue
    fi
    if [[ ! "$line" =~ = ]]; then
      echo "$line" >> "$temp_file"; continue
    fi

    local key="${line%%=*}"
    local value="${line#*=}"

    if [[ -z "$value" ]]; then
      echo "$line" >> "$temp_file"; continue
    fi

    # Skip already encrypted values (idempotency)
    if [[ "$value" =~ ^ENC\(.+\)$ ]]; then
      echo "$line" >> "$temp_file"; continue
    fi

    local encrypted_value
    encrypted_value=$(encrypt_value "$value" "$password")

    if [[ -z "$encrypted_value" ]]; then
      print_error "Failed to encrypt value for key: $key"
      rm -f "$temp_file"
      return 1
    fi

    echo "${key}=ENC(${encrypted_value})" >> "$temp_file"
  done < "$file"

  mv "$temp_file" "$file"
  return 0
}

decrypt_file() {
  local file="$1"
  local password="$2"
  local temp_file
  temp_file=$(mktemp)

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" ]]; then
      echo "" >> "$temp_file"; continue
    fi
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
      echo "$line" >> "$temp_file"; continue
    fi
    if [[ ! "$line" =~ = ]]; then
      echo "$line" >> "$temp_file"; continue
    fi

    local key="${line%%=*}"
    local value="${line#*=}"

    if [[ -z "$value" ]]; then
      echo "$line" >> "$temp_file"; continue
    fi

    if [[ "$value" =~ ^ENC\((.+)\)$ ]]; then
      local ciphertext="${BASH_REMATCH[1]}"
      local decrypted_value
      decrypted_value=$(decrypt_value "$ciphertext" "$password") || true

      if [[ -z "$decrypted_value" ]]; then
        rm -f "$temp_file"
        return 1
      fi

      echo "${key}=${decrypted_value}" >> "$temp_file"
    else
      echo "$line" >> "$temp_file"
    fi
  done < "$file"

  mv "$temp_file" "$file"
  return 0
}

# -----------------------------------------------------------------------------
# Dotfile: load entries into parallel arrays
#   _ec_names[]      — project names (without leading *)
#   _ec_paths[]      — absolute .env paths
#   _ec_default_idx  — 0-based index of the default entry
# -----------------------------------------------------------------------------

_ec_names=()
_ec_paths=()
_ec_default_idx=0

load_dotfile() {
  _ec_names=()
  _ec_paths=()
  _ec_default_idx=0

  [[ ! -f "$DOTFILE" ]] && return

  local i=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ ! "$line" =~ = ]] && continue

    local raw_name="${line%%=*}"
    local raw_path="${line#*=}"

    # Strip surrounding whitespace from path
    raw_path="${raw_path#"${raw_path%%[![:space:]]*}"}"
    raw_path="${raw_path%"${raw_path##*[![:space:]]}"}"

    if [[ "$raw_name" == \** ]]; then
      raw_name="${raw_name#\*}"
      _ec_default_idx=$i
    fi

    _ec_names+=("$raw_name")
    _ec_paths+=("$raw_path")
    ((i++)) || true
  done < "$DOTFILE"
}

# Write the parallel arrays back to the dotfile atomically
save_dotfile() {
  local temp_file
  temp_file=$(mktemp)

  local i
  for i in "${!_ec_names[@]}"; do
    if [[ $i -eq $_ec_default_idx ]]; then
      echo "*${_ec_names[$i]}=${_ec_paths[$i]}" >> "$temp_file"
    else
      echo "${_ec_names[$i]}=${_ec_paths[$i]}" >> "$temp_file"
    fi
  done

  mv "$temp_file" "$DOTFILE"
}

# Resolve a raw user-supplied path to an absolute path, verify it exists
resolve_env_path() {
  local raw="$1"
  local resolved
  # Resolve relative paths against SCRIPT_DIR so the result is the same
  # regardless of which directory the user ran the script from.
  if [[ "$raw" != /* ]]; then
    raw="${SCRIPT_DIR}/${raw}"
  fi
  resolved="$(cd "$(dirname "$raw")" 2>/dev/null && pwd)/$(basename "$raw")" || {
    print_error "Cannot resolve path: $raw"
    return 1
  }
  if [[ ! -f "$resolved" ]]; then
    print_error "File not found: $resolved"
    return 1
  fi
  echo "$resolved"
}

# -----------------------------------------------------------------------------
# First-run setup
# -----------------------------------------------------------------------------

first_run_setup() {
  echo "No projects configured. Let's set one up."
  echo "─────────────────────────────────────────────────────"
  echo ""

  local new_name=""
  while [[ -z "$new_name" ]]; do
    read_line "  Project name: " new_name
    new_name="${new_name#"${new_name%%[![:space:]]*}"}"
    new_name="${new_name%"${new_name##*[![:space:]]}"}"
    [[ -z "$new_name" ]] && print_error "Project name cannot be empty."
  done

  local new_path=""
  while true; do
    read_line "  Path to .env (absolute, or relative to the envcrypt directory): " new_path
    new_path="${new_path#"${new_path%%[![:space:]]*}"}"
    new_path="${new_path%"${new_path##*[![:space:]]}"}"
    if [[ -z "$new_path" ]]; then
      print_error "Path cannot be empty."
      continue
    fi
    local resolved
    resolved=$(resolve_env_path "$new_path") && break
    # resolve_env_path already printed the error; loop to re-prompt
  done

  echo ""
  # Write fresh dotfile — first entry is automatically the default
  echo "*${new_name}=${resolved}" > "$DOTFILE"

  print_success "Project \"$new_name\" saved as default."
  echo "  Stored path: $resolved"
  echo ""
}

# -----------------------------------------------------------------------------
# Add project (appended to dotfile, not set as default)
# -----------------------------------------------------------------------------

add_project() {
  echo ""
  echo "Add a new project"
  echo "─────────────────────────────────────────────────────"

  local new_name=""
  while [[ -z "$new_name" ]]; do
    read_line "  Project name: " new_name
    new_name="${new_name#"${new_name%%[![:space:]]*}"}"
    new_name="${new_name%"${new_name##*[![:space:]]}"}"
    [[ -z "$new_name" ]] && print_error "Project name cannot be empty."
  done

  local new_path=""
  while true; do
    read_line "  Path to .env (absolute, or relative to the envcrypt directory): " new_path
    new_path="${new_path#"${new_path%%[![:space:]]*}"}"
    new_path="${new_path%"${new_path##*[![:space:]]}"}"
    if [[ -z "$new_path" ]]; then
      print_error "Path cannot be empty."
      continue
    fi
    local resolved
    resolved=$(resolve_env_path "$new_path") && break
  done

  _ec_names+=("$new_name")
  _ec_paths+=("$resolved")
  save_dotfile

  echo ""
  print_success "Added \"$new_name\""
  echo "  Stored path: $resolved"
  echo "  To make it the default, choose 'd' from the project menu."
  echo ""
}

# -----------------------------------------------------------------------------
# Change default
# -----------------------------------------------------------------------------

change_default() {
  local count=${#_ec_names[@]}
  echo ""
  echo "Change default project"
  echo "─────────────────────────────────────────────────────"

  local i
  for i in "${!_ec_names[@]}"; do
    local marker="  "
    [[ $i -eq $_ec_default_idx ]] && marker="* "
    printf "  %d) %s%s\n" "$((i+1))" "$marker" "${_ec_names[$i]}"
    printf "        %s\n" "${_ec_paths[$i]}"
  done

  echo ""
  while true; do
    local choice=""
    read_line "  Set default [1-${count}]: " choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= count )); then
      _ec_default_idx=$(( choice - 1 ))
      save_dotfile
      echo ""
      print_success "Default set to \"${_ec_names[$_ec_default_idx]}\""
      echo ""
      return
    else
      print_error "Please enter a number between 1 and ${count}."
    fi
  done
}

# -----------------------------------------------------------------------------
# Project selection menu — sets target_file in the caller's scope
# -----------------------------------------------------------------------------

select_project() {
  load_dotfile
  local count=${#_ec_names[@]}

  if [[ $count -eq 0 ]]; then
    first_run_setup
    load_dotfile
    count=${#_ec_names[@]}
    if [[ $count -eq 0 ]]; then
      print_error "No projects configured. Exiting."
      exit 1
    fi
  fi

  while true; do
    local default_name="${_ec_names[$_ec_default_idx]}"
    local default_path="${_ec_paths[$_ec_default_idx]}"

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Select project:"
    echo ""

    local i
    for i in "${!_ec_names[@]}"; do
      local marker="  "
      local tag=""
      if [[ $i -eq $_ec_default_idx ]]; then
        marker="* "
        tag="  [default]"
      fi
      printf "  %d) %s%s%s\n" "$((i+1))" "$marker" "${_ec_names[$i]}" "$tag"
      printf "        %s\n" "${_ec_paths[$i]}"
    done

    echo ""
    echo "  a) Add a new project"
    echo "  d) Change default"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    local choice=""
    read_line "  Choice [ENTER for default]: " choice
    echo ""

    if [[ -z "$choice" ]]; then
      target_file="$default_path"
      target_project="$default_name"
      break
    elif [[ "$choice" =~ ^[0-9]+$ ]]; then
      local idx=$(( choice - 1 ))
      if (( idx >= 0 && idx < ${#_ec_names[@]} )); then
        target_file="${_ec_paths[$idx]}"
        target_project="${_ec_names[$idx]}"
        break
      else
        print_error "Invalid selection. Please choose 1–${#_ec_names[@]}, a, or d."
        echo ""
      fi
    elif [[ "$choice" == "a" || "$choice" == "A" ]]; then
      add_project
      load_dotfile
    elif [[ "$choice" == "d" || "$choice" == "D" ]]; then
      change_default
      load_dotfile
    else
      print_error "Invalid input. Please choose 1–${#_ec_names[@]}, a, or d."
      echo ""
    fi
  done

  if [[ ! -f "$target_file" ]]; then
    print_error "File not found: $target_file"
    print_error "Check the path in $DOTFILE and try again."
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Detect operation mode from file contents
# Returns 0 (encrypted / should unlock) or 1 (plaintext / should encrypt)
# -----------------------------------------------------------------------------

file_is_encrypted() {
  local file="$1"
  grep -q '=ENC(.\+)' "$file" 2>/dev/null
}

# -----------------------------------------------------------------------------
# ENCRYPT mode
# -----------------------------------------------------------------------------

run_encrypt() {
  # Verify there's actually something to encrypt
  local has_plaintext=false
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ ! "$line" =~ = ]] && continue
    local value="${line#*=}"
    [[ -z "$value" ]] && continue
    [[ "$value" =~ ^ENC\(.+\)$ ]] && continue
    has_plaintext=true
    break
  done < "$target_file"

  if [[ "$has_plaintext" == false ]]; then
    print_error "No plaintext values found to encrypt."
    exit 1
  fi

  # Password prompt
  local password=""
  read_password "Enter encryption password: " password

  if [[ -z "$password" ]]; then
    print_error "Password cannot be empty."
    exit 1
  fi

  local password_confirm=""
  read_password "Confirm encryption password: " password_confirm

  if [[ "$password" != "$password_confirm" ]]; then
    print_error "Passwords do not match."
    unset password password_confirm
    exit 1
  fi
  unset password_confirm

  # Encrypt
  local temp_file encrypted_count=0 skipped_count=0
  temp_file=$(mktemp)

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "$line" ]]; then
      echo "" >> "$temp_file"; continue
    fi
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
      echo "$line" >> "$temp_file"; continue
    fi
    if [[ ! "$line" =~ = ]]; then
      echo "$line" >> "$temp_file"; continue
    fi

    local key="${line%%=*}"
    local value="${line#*=}"

    if [[ -z "$value" ]]; then
      echo "$line" >> "$temp_file"; continue
    fi

    if [[ "$value" =~ ^ENC\(.+\)$ ]]; then
      echo "$line" >> "$temp_file"
      ((skipped_count++)) || true
      continue
    fi

    local encrypted_value
    encrypted_value=$(encrypt_value "$value" "$password")

    if [[ -z "$encrypted_value" ]]; then
      print_error "Failed to encrypt value for key: $key"
      rm -f "$temp_file"
      unset password
      exit 1
    fi

    echo "${key}=ENC(${encrypted_value})" >> "$temp_file"
    ((encrypted_count++)) || true
  done < "$target_file"

  mv "$temp_file" "$target_file"
  unset password

  echo ""
  print_success "Encryption complete."
  echo "  File:             $target_file"
  echo "  Values encrypted: $encrypted_count"
  if [[ $skipped_count -gt 0 ]]; then
    echo "  Already encrypted (skipped): $skipped_count"
  fi
}

# -----------------------------------------------------------------------------
# UNLOCK mode
# -----------------------------------------------------------------------------

run_unlock() {
  # Duration prompt
  echo "Select decryption duration:"
  echo "  1) 1 minute"
  echo "  2) 2 minutes"
  echo "  3) 5 minutes"
  echo ""
  local duration_choice=""
  read_line "Choice [1/2/3]: " duration_choice

  local duration_seconds duration_label
  case "$duration_choice" in
    1) duration_seconds=60;  duration_label="1 minute" ;;
    2) duration_seconds=120; duration_label="2 minutes" ;;
    3) duration_seconds=300; duration_label="5 minutes" ;;
    *)
      print_error "Invalid choice. Exiting."
      exit 1
      ;;
  esac
  echo ""

  # Extract the first ENC(...) value to verify the password against
  local first_encrypted_line first_ciphertext
  first_encrypted_line=$(grep '=ENC(.\+)' "$target_file" | head -n 1)
  first_ciphertext="${first_encrypted_line#*=ENC(}"
  first_ciphertext="${first_ciphertext%)}"

  # Password prompt with retry
  local password="" attempts=0
  while [[ $attempts -lt $MAX_PASSWORD_ATTEMPTS ]]; do
    local password_attempt=""
    read_password "Enter decryption password: " password_attempt

    local test_decrypt
    test_decrypt=$(decrypt_value "$first_ciphertext" "$password_attempt" 2>/dev/null) || true

    if [[ -n "$test_decrypt" ]]; then
      password="$password_attempt"
      unset password_attempt
      break
    fi

    ((attempts++)) || true
    local remaining=$(( MAX_PASSWORD_ATTEMPTS - attempts ))
    if [[ $remaining -gt 0 ]]; then
      print_error "Incorrect password. $remaining attempt(s) remaining."
    else
      print_error "Incorrect password."
    fi
    unset password_attempt
  done

  if [[ -z "$password" ]]; then
    echo ""
    print_error "Maximum attempts exceeded. Exiting."
    echo "  If you've forgotten your password, restore the .env from a backup" >&2
    echo "  and re-encrypt with envcrypt.sh." >&2
    exit 1
  fi

  # Override SIGINT for the decrypted window: re-encrypt before exiting.
  reencrypt_and_exit() {
    echo ""
    echo "Interrupt received. Re-encrypting $target_file before exit..."
    if encrypt_file "$target_file" "$password"; then
      print_success "Re-encrypted: $target_file"
    else
      print_error "Failed to re-encrypt! Run envcrypt.sh manually to secure the file."
    fi
    unset password
    exit 0
  }
  trap 'reencrypt_and_exit' SIGINT SIGTERM

  # Decrypt
  if decrypt_file "$target_file" "$password"; then
    echo ""
    print_success "Decrypted: $target_file"
    echo "  Values will be re-encrypted in ${duration_label}."
    echo "  Press Ctrl+C to re-encrypt and exit early."
    echo ""
  else
    print_error "Decryption failed unexpectedly. The file may be in an inconsistent state."
    print_error "Restore the file from a backup and re-encrypt with envcrypt.sh."
    unset password
    exit 1
  fi

  # Countdown timer
  local remaining_seconds=$duration_seconds
  while [[ $remaining_seconds -gt 0 ]]; do
    if [[ $remaining_seconds -ge 60 ]]; then
      local remaining_minutes=$(( (remaining_seconds + 59) / 60 ))
      local unit="minute"
      [[ $remaining_minutes -gt 1 ]] && unit="minutes"
      printf "\r  Re-encrypting in ~%d %s...  " "$remaining_minutes" "$unit"
    else
      printf "\r  Re-encrypting in %d seconds...  " "$remaining_seconds"
    fi

    local sleep_interval=30
    [[ $remaining_seconds -lt 30 ]] && sleep_interval=$remaining_seconds

    sleep "$sleep_interval"
    remaining_seconds=$(( remaining_seconds - sleep_interval ))
  done

  echo ""
  echo ""

  # Re-encrypt — file is safe again, restore default signal behaviour
  echo "Duration expired. Re-encrypting $target_file..."
  trap '_on_sigint' SIGINT SIGTERM

  if encrypt_file "$target_file" "$password"; then
    print_success "Re-encrypted: $target_file"
    echo "  Goodbye."
  else
    print_error "Failed to re-encrypt! Run envcrypt.sh manually to secure the file."
  fi

  unset password
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

target_file=""
target_project=""
select_project

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if file_is_encrypted "$target_file"; then
  echo "  Mode:        unlock  (encrypted values detected)"
  echo "  Project:     $target_project"
  echo "  Target file: $target_file"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  run_unlock
else
  echo "  Mode:        encrypt  (no encrypted values detected)"
  echo "  Project:     $target_project"
  echo "  Target file: $target_file"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  run_encrypt
fi
