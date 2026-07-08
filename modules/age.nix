###! # AGENIX — NiXium maintainer fork
###!
###! SUMMARY: Full NiXium fork of agenix.  Per-secret systemd services with
###! unique exit codes (0=authentic, 1=missing, 2=degraded, 4=integrity
###! violation).  Ghost Identity architecture for HNDL-resistant key derivation.
###! Persistent agenix-agent (mlocked heap, Unix socket, get-secret subcommand).
###! Direct pipe deployment to target paths (no /run/agenix ramfs).  Inline
###! secret injection into config files with placeholder derivation from check
###! presets.  rage default with NTRU Prime.  Initrd Dispatcher for slot-based
###! generation switching via kexec.  Pluggable bootstrap providers (FIDO2,
###! password, future network).  User-level secrets via pam_agenix.so (age-home.nix).
###!
###! Data flow (one time per boot):
###!
###!   LUKS Passphrase + StableSalt ---> Argon2id(preferred) / PBKDF2(option) ---> IdentityKey
###!                                                            |
###!                                                            v
###!                                                  agenix-agent serve
###!                                                  (mlock, socket, persist)
###!                                                            |
###!                      +-------------------------------------+
###!                      v                                     v
###!             neededForBoot secrets              Per-secret services
###!             (activation script)               (agent get-secret at runtime)
###!                      |                                     |
###!                      v                                     v
###!             Direct pipe to target               Direct pipe to target
###!             + anchored check                   + anchored check
###!             + inject (if config)               + inject (if config)
###!
###! ## WHY THIS FILE EXISTS
###!
###! Upstream agenix has three fatal flaws for NiXium's multi-machine fleet:
###!
###!   1. MONOLITHIC FAILURE -- all secrets decrypt in ONE activation script.
###!      No per-secret visibility in `systemctl --failed`, no per-secret
###!      fallback, no way to know WHICH secret broke without reading the
###!      full activation log.
###!
###!   2. BOOTSTRAP CIRCULARITY -- `identityPaths` defaulted to SSH host keys,
###!      which were THEMSELVES agenix secrets.  The identity must exist
###!      BEFORE the secret that provides it can be decrypted.
###!
###!   3. NO HNDL DEFENSE -- upstream provides no protection against "Harvest
###!      Now, Decrypt Later" attacks.  Static, predictable salt (machine-id)
###!      means an attacker with a disk image can eventually brute-force
###!      the passphrase offline.
###!
###! ## AGENT ARCHITECTURE
###!
###! agenix-agent is the core runtime component.  It holds the IdentityKey in
###! mlocked heap memory and provides a Unix socket interface for decryption.
###! The key never leaves the agent process -- no get-key subcommand exists.
###!
###! ### Lifecycle
###!
###! 1. BOOT: Initrd derives IdentityKey.  Agent starts, receives key on stdin.
###! 2. PERSIST: Agent mlock()s the key buffer (prevents swap to disk).  Opens
###!    Unix socket at /run/agenix.sock (system) or /run/user/UID/agenix.sock
###!    (user).  Responds to get-secret requests on the socket.
###! 3. ACTIVATION: Activation scripts and per-secret services call
###!    agenix-agent get-secret <name> to decrypt .age files.
###! 4. SHUTDOWN: Systemd sends SIGTERM.  Agent memset()s the key buffer,
###!    closes the socket, exits.
###! 5. CRASH: If agent crashes, already-deployed secrets remain accessible
###!    at their target paths.  Only new decryption (nixos-rebuild switch)
###!    fails until next boot.  No damage control via agent kill -- secrets
###!    are already at target paths.
###!
###! ### Socket Protocol
###!
###!   Socket: /run/agenix.sock (mode 0600, root-only)
###!   Protocol: get-secret <name>
###!   Response: Decrypted secret content on stdout
###!   Error: Non-zero exit, error message on stderr
###!   Agent maps <name> to .age file paths from its internal manifest.
###!
###! ### Audit
###!
###!   Agent supports --audit=path/to/file for remote logging.
###!   When no --audit flag is passed, no audit log is written.
###!   Audit format: timestamp | secret-name | exit-code | identity-slot
###!   Default: disabled.  Must be explicitly enabled.
###!
###! ### Interface
###!
###!   agenix-agent serve              Start agent, read key from stdin
###!   agenix-agent get-secret <name>  Decrypt secret via socket, output to stdout
###!   agenix-agent stop               Send SIGTERM, wipe key, exit
###!
###! ## GHOST IDENTITY PIPELINE
###!
###! The unified identity model used by ALL entities (machine, admin, user):
###!
###!   BootstrapKey                       Passphrase
###!       |                                  |
###!       v                                  v
###!   salt.age --Decrypt--> StableSalt --Argon2id(preferred)/PBKDF2(option)--> IdentityKey
###!                                                      |
###!                                                      v
###!                                              agenix-agent (mlock, socket)
###!
###! ### Stage 1: Bootstrap (auth provider)
###!   Input:  Hardware key or bootstrap passphrase.
###!   Output: BootstrapKey (32 bytes).
###!   Provider chain: configurable order, first success wins.
###!
###! ### Stage 2: Salt Recovery
###!   Input:  BootstrapKey + salt.age (encrypted file in Nix store).
###!   Process: age --decrypt -i <bootstrap_key> salt.age -> StableSalt.
###!   Output: StableSalt -- high-entropy, deterministic, machine-unique.
###!   HNDL note: an attacker with disk image CANNOT obtain StableSalt
###!   because salt.age is encrypted with the BootstrapKey.
###!
###! ### Stage 3: Identity Derivation
###!   Input:  LUKS Slot Passphrase + StableSalt.
###!   Process: Argon2id(passphrase, salt=StableSalt, preferred) or PBKDF2(passphrase, salt=StableSalt, option) -> 32 bytes.
###!   Output: IdentityKey -- age-compatible X25519 private key
###!           (clamped per RFC 7748).  Piped into agenix-agent via stdin.
###!
###! ### Key Properties
###!
###!   DETERMINISTIC: Same passphrase + same StableSalt -> same IdentityKey.
###!   REPRODUCIBLE: Rebuild from scratch with same passphrase + hardware key.
###!   HNDL-PROOF: Attacker with disk image lacks StableSalt (it's encrypted).
###!
###! ## THREAT MODEL: HARVEST NOW, DECRYPT LATER (HNDL)
###!
###! HNDL is the primary long-term threat.  An attacker who captures a disk
###! image today has all encrypted .age files.  With a quantum computer running
###! Grover's algorithm, a 128-bit passphrase search becomes 64-bit effective.
###!
###! The Ghost Identity neutralizes this:
###!   - The salt is itself ENCRYPTED (salt.age).
###!   - To brute-force the passphrase, the attacker must FIRST decrypt salt.age.
###!   - Decrypting salt.age requires the BootstrapKey (hardware or password).
###!   - With a hardware key, brute-force is impossible (no physical access).
###!   - Even with both disk AND bootstrap password, two KDF rounds square
###!     the attack cost.
###!
###! This HNDL defense applies to ALL identity types (machine, admin, user)
###! via the same Ghost Identity pipeline.  No identity key is ever stored
###! in plaintext -- only passphrase-encrypted identity archives in the repo.
###!
###! ## ENTITY TYPES
###!
###! Every entity follows the same Ghost Identity pipeline.  The Passphrase
###! source differs per entity type:
###!
###! ### Machine (system-level)
###!   BootstrapKey: FIDO2 or initrd prompt.
###!   Passphrase:   LUKS slot passphrase (typed at boot).
###!   Agent socket: /run/agenix.sock
###!   Decrypts:     System secrets (SSH, Tor, WireGuard, VPN, etc.).
###!   Managed by:   age.nix (this module) + Initrd Dispatcher + agent.
###!
###! ### Admin (build-time validation)
###!   BootstrapKey: FIDO2 or admin password.
###!   Passphrase:   Deployment passphrase.
###!   Agent:        ssh-agent on admin's dev machine.
###!   Decrypts:     All .age files in secrets.nix for validation.
###!   Managed by:   agenix encrypt/check tooling.
###!   Repository:   admin-identity.age (passphrase-encrypted in repo).
###!
###! ### User (home-manager)
###!   BootstrapKey: PAM (login password) or optional FIDO2.
###!   Passphrase:   Login password.
###!   Agent socket: /run/user/UID/agenix.sock
###!   Decrypts:     User secrets (SSH keys, tokens, GPG keys).
###!   Managed by:   age-home.nix + pam_agenix.so.
###!   Repository:   user-identity.<name>.age in per-user config.
###!
###! ## HARDWARE ROOT OF TRUST POLICY
###!
###! This fork explicitly REJECTS TPM-based and TrustZone-based roots of trust:
###!   1. Proprietary firmware cannot be audited (Intel PTT, AMD fTPM, etc.).
###!   2. TPMs tie identity to a motherboard, preventing hardware migration.
###!   3. NiXium targets CANOBOOT (x86), ARM, and RISC-V -- TPM support is
###!      uneven or nonexistent on open firmware.
###!
###! Preferred (in priority order):
###!   1. External FIDO2/U2F hardware keys -- auditable, portable, user-controlled.
###!   2. Bootstrap passphrase -- fallback until hardware key is obtained.
###!   3. Network-based auth -- future option for remote attestation.
###!
###! ## BOOTSTRAP PROVIDERS
###!
###! Pluggable auth provider layer produces the BootstrapKey.
###! Tried in order per entity type; first success wins.
###!
###! ### auth.bootstrap.fido2 (hardware key, preferred)
###!   Uses FIDO2/U2F token's HMAC-SECRET extension to derive a
###!   hardware-bound key.  Token must be present at boot.
###!
###! ### auth.bootstrap.password (fallback)
###!   Uses a passphrase entered at a prompt.  Configurable retries
###!   (default 3), then boot proceeds in degraded mode.
###!
###! ### auth.bootstrap.network (future)
###!   Uses a remote attestation server to push the BootstrapKey.
###!
###! ## INITRD DISPATCHER
###!
###! The Initrd Dispatcher is the producer of the Machine IdentityKey.
###! It is a SEPARATE NixOS module (not part of agenix) that agenix and
###! the agent consume.  Its responsibilities:
###!
###!   1. PRESENT LUKS PROMPT -- standard cryptsetup behavior.
###!   2. SLOT DETECTION -- identify which LUKS slot was unlocked.
###!   3. BOOTSTRAP CHAIN -- run auth providers in order (FIDO2 -> password).
###!   4. SALT RECOVERY -- BootstrapKey -> salt.age -> StableSalt.
###!   5. IDENTITY DERIVATION -- StableSalt + Passphrase -> IdentityKey.
###!   6. AGENT START -- pipe IdentityKey to agenix-agent serve.
###!   7. GENERATION DISPATCH -- map slot to generation label, kexec.
###!
###! ### Generation Dispatching
###!
###! The slot-to-generation mapping is CONFIGURABLE via the Initrd
###! Dispatcher module.  Documentation example -- NOT hardcoded:
###!
###!   boot.initrd.luks.slotMap = {
###!     0 = "production";   # Standard NixOS generation
###!     1 = "guest";        # Limited, user-friendly generation
###!     2 = "kitty";        # Panic/deception generation
###!   };
###!
###! Slot 0 (Production):  Agent holds full IdentityKey, full secrets deployed.
###! Slot 1 (Guest):        Guest passphrase, GNOME, no infra access.
###! Slot 2 (Kitty):        Panic password, functional-looking deception layer,
###!                        theft reporting (future: Zappix), prevents bootloader
###!                        tampering, enables remote recovery.
###!
###! Bait mechanism: panic password written on laptop sticker.  Thief enters it
###! --> Kitty generation boots --> looks functional --> silently reports theft.
###! Agent wipes production key, holds only kitty-tier IdentityKey.
###! Different LUKS passphrase --> different IdentityKey --> different secrets.
###!
###! ## DEPLOYMENT MODEL (No /run/agenix)
###!
###! This fork ELIMINATES the upstream /run/agenix ramfs entirely:
###!
###!   REMOVED: secretsMountPoint, secretsDir, newGeneration activation script,
###!            generation directories, symlinks, chown activation script.
###!
###! Secrets are deployed DIRECTLY to their target paths:
###!
###!   agenix-agent get-secret <name> > age.secrets.<name>.path
###!
###! This eliminates:
###!   - Ramfs mount complexity (prevents bind-mount conflicts)
###!   - Generation directory cleanup (stale secrets after switch)
###!   - Symlink management (broken symlinks on cleanup)
###!   - chown script (files land with correct ownership from the agent)
###!
###! ## INJECTION MODEL (Inline Secrets)
###!
###! For secrets that must be embedded in configuration files (API tokens,
###! database passwords), the inject option patches the target file:
###!
###!   age.secrets.my-api-key.inject = [ "/etc/myapp.conf" ];
###!
###! ### Placeholder Derivation
###!
###! The placeholder is automatically derived from age.secrets.<name>.check:
###!
###!   "tor"         -> valid onion key placeholder (ED25519-V3:...)
###!   "ssh-key"     -> valid SSH key header placeholder
###!   "wireguard"   -> valid WireGuard base64 key placeholder
###!   custom regex  -> unique marker __AGE_MARKER_<name>__
###!
###! The placeholder is available to Nix expressions via:
###!   age.secrets.<name>.placeholder
###!
###! This evaluates at build time to the marker string.  Config templates
###! reference it:
###!
###!   environment.etc."myapp.conf".text = ''
###!     api_key = ${age.secrets.my-api-key.placeholder}
###!   '';
###!
###! ### Activation Flow
###!
###! The per-secret service runs at activation/systemd start:
###!
###!   1. agenix-agent get-secret <name> > $target_path
###!   2. chmod $mode $target_path
###!   3. For each path in age.secrets.<name>.inject:
###!      a. Read the config file
###!      b. Replace placeholder with decrypted secret
###!      c. Atomic write: .tmp in same dir, then rename
###!   4. grep -E "$check" $target_path || exit 4
###!   5. exit 0
###!
###! The check validates both format AND write completeness (regex anchored to $).
###! Partial writes from interrupted pipes fail the anchored check.
###! No .tmp file needed for the secret itself -- direct pipe suffices.
###!
###! ### Placeholder Override
###!
###! If automatic placeholder derivation produces a value that fails service
###! build-time validation, an explicit placeholder can be set:
###!
###!   age.secrets.my-tor-key.placeholder = "ED25519-V3:__CUSTOM_FAKE__";
###!
###! ## EXIT CODES
###!
###!   0 -- Authentic (decrypted + check passed -> deployed).
###!   1 -- Missing (decrypt failed, no fallback available).
###!   2 -- Degraded (decrypt failed, fallback script generated content).
###!   4 -- Integrity violation (decrypted but check regex failed -- no fallback).
###!
###! Systemd has no "DEGRADED" state.  Unique exit codes let monitoring
###! distinguish root causes via systemctl show <unit>.
###!
###! ## EXECSTART PSEUDOCODE
###!
###!   agent get-secret $name > $target_path
###!   if agent returned non-zero:
###!     if fallback.enable:
###!       fallback.script > $target_path
###!       chmod $mode $target_path
###!       exit 2                        # Degraded
###!     else:
###!       exit 1                        # Missing
###!   else:
###!     chmod $mode $target_path
###!     if inject paths set:
###!       for path in inject:
###!         read file
###!         replace placeholder with $secret
###!         atomic write (same dir, .tmp + rename)
###!     if check set:
###!       grep -E "$check" $target_path || exit 4
###!     exit 0
###!
###! ## ACTIVATION SCRIPT ORDERING
###!
###! The agent removes the need for most upstream activation scripts.
###! Removed: agenixNewGeneration, agenixInstall, agenixChown, agenix.
###!
###!   specialfs
###!     +-- users (create users -- may need hashedPasswordFile)
###!     +-- groups (create groups)
###!
###! neededForBoot secrets use the agent during activation (agent is available
###! because it started in initrd and persisted through switch_root).
###! The activation script for neededForBoot calls:
###!   agenix-agent get-secret <name> > <path>
###!
###! All other secrets use per-secret systemd services with Before= targeting
###! the service that owns the config file or path.
###!
###! ## ENCRYPTION WORKFLOW
###!
###! ### agenix encrypt
###!
###! CLI tool that creates .age files for deployment (runs on admin machine):
###!   1. Reads the plaintext secret (from stdin or file).
###!   2. Reads age.secrets.<name>.check from the Nix config.
###!   3. Validates plaintext against check (regex or preset).
###!   4. Encrypts to all recipients listed in secrets.nix using rage.
###!   5. Fails if check validation fails (prevents broken deployments).
###!
###! Recipients in secrets.nix are PQ public keys (from Ghost Identity).
###! Format:
###!
###!   "./secrets/tor-key.age".publicKeys = [
###!     sinnenfreude-machine       # Machine's PQ public key
###!     kreyren-admin              # Admin's PQ public key
###!     jane-user                  # User's PQ public key (if applicable)
###!   ];
###!
###! ### agenix check
###!
###! Build-time validation tool run on admin machine before deployment:
###!   1. Reads admin-identity.age from repo.
###!   2. Checks ssh-agent for admin key (or prompts for passphrase).
###!   3. For each secret in config.age.secrets:
###!      a. Decrypts the .age file with admin key.
###!      b. Validates content against age.secrets.<name>.check.
###!   4. Exits 0 if all pass; exits 1 on any failure, blocking deploy.
###!
###! This validation is PURE (runs on admin machine, not during Nix build).
###! The Nix build copies only .age files to the store (deterministic).
###!
###! ### User Secrets (Zero-Trust)
###!
###! User secrets are encrypted to the USER's public key, not the admin's.
###! agenix check skips user secrets if the admin's key is not listed.
###! User-side validation runs via the user's own agent on their machine.
###!
###! ## PUBLIC API
###!
###! age.package (package, default=pkgs.rage)
###!   The age binary.  rage default for NTRU Prime plugin support.
###!   Plugins bundled into this derivation.
###!
###! age.secrets.<name>.file (types.path, REQUIRED)
###!   Path to the .age-encrypted file in the Nix store.
###!
###! age.secrets.<name>.path (str, default=/run/agenix/<name>)
###!   Destination path for the decrypted secret.
###!   No intermediate ramfs -- written directly via agent pipe.
###!
###! age.secrets.<name>.neededForBoot (bool, default=false)
###!   Decrypt in activation script (agent is available from initrd).
###!
###! age.secrets.<name>.fallback (submodule)
###!   .enable (bool, default=false)
###!     If false and decrypt fails -> exit 1 (missing).
###!     If true and decrypt fails -> run script -> exit 2 (degraded).
###!   .script (nullOr lines, default=null)
###!     Shell script generating secret content (stdout).
###!
###! age.secrets.<name>.check (nullOr str, default=null)
###!   Regex pattern or preset name to validate decrypted content.
###!   Evaluated at build time (via agenix check) AND at runtime.
###!   Runtime check failure -> exit 4 (no fallback).
###!   Presets (resolved via lib helper):
###!     "tor" -- validates ed25519 onion key format.
###!     "ssh-key" -- validates SSH private key header.
###!     "wireguard" -- validates WireGuard private key format.
###!     Any other string -- treated as literal regex.
###!
###! age.secrets.<name>.inject (list of str, default=[])
###!   Configuration files to patch with the decrypted secret.
###!   Placeholder derived from check preset automatically.
###!   Example: inject = [ "/etc/tor/torrc" ];
###!
###! age.secrets.<name>.placeholder (nullOr str, default=null)
###!   Override the automatic placeholder derivation.
###!   If null, derived from check preset (see Injection Model section).
###!   Set explicitly when the automatic placeholder fails service validation.
###!
###! age.secrets.<name>.mode (str, default="0400")
###! age.secrets.<name>.owner (str, default="0")
###! age.secrets.<name>.group (str, default=users.<owner>.group)
###! age.secrets.<name>.after (list of str, default=[])
###!
###! ## DEPRECATIONS FROM UPSTREAM
###!
###! REMOVED:
###!   - age.identityPaths -- broken by Ghost Identity.  Sole identity is
###!     the IdentityKey held by agenix-agent, derived from LUKS passphrase.
###!   - age.ageBin -- replaced by age.package (derivation, not string).
###!   - age.pluginDir -- bundle plugins into age.package derivation.
###!   - age.secretsDir (was /run/agenix) -- removed.  Secrets go directly
###!     to age.secrets.<name>.path.  No ramfs, no generations, no symlinks.
###!   - age.secretsMountPoint (was /run/agenix.d) -- removed.
###!   - age.secrets.<name>.symlink -- removed (no ramfs to symlink from).
###!
###! ADDED:
###!   - age.secrets.<name>.check (nullOr str -- regex or preset)
###!   - age.secrets.<name>.fallback (submodule {enable, script})
###!   - age.secrets.<name>.neededForBoot (bool)
###!   - age.secrets.<name>.inject (list of str)
###!   - age.secrets.<name>.placeholder (nullOr str)
###!   - age.secrets.<name>.after (list of str)
###!
###! CHANGED:
###!   - age.package default -> pkgs.rage (was pkgs.age).
###!     rage supports plugins (NTRU Prime); age (Go) does not.
###!
###! ## KEY DESIGN DECISIONS
###!
###! 1. SINGLE SERVICE PER SECRET
###!    The per-secret systemd service handles decrypt, check, inject, and
###!    fallback in a single ExecStart.  No OnFailure=, no second unit.
###!    Before= targets the service that owns the config file or path.
###!
###! 2. NO /run/agenix RAMFS
###!    Removed entirely.  Secrets go directly to target paths via agent pipe.
###!    No generation directories, no symlinks, no chown scripts.
###!    Reduces attack surface, eliminates stale-secret bugs.
###!
###! 3. AGENT PERSISTS WITH KEY
###!    agenix-agent holds IdentityKey in mlocked heap memory, serves via Unix
###!    socket.  Key never written to a file.  memset() on shutdown/stop.
###!    Available for both activation scripts and systemd services.
###!    Agent crash does not affect already-deployed secrets.
###!
###! 4. CHECK ANCHORED TO END
###!    Regex presets and custom patterns must anchor to $ for completeness.
###!    Partial writes from interrupted pipes fail the anchored check.
###!    No .tmp file needed for the secret path -- check guarantees integrity.
###!
###! 5. INJECT PLACEHOLDER FROM CHECK
###!    Placeholder is derived from the check preset automatically.
###!    Admin never sets placeholder in 95% of cases.
###!    Override exists for edge cases where auto-derivation fails.
###!
###! 6. ZERO-TRUST FOR USER SECRETS
###!    Admin key cannot decrypt user secrets.  User secrets are encrypted
###!    to the user's public key only.  agenix check skips user secrets
###!    unless the admin's key is explicitly listed as a recipient.
###!
###! 7. ANTI-TPM, FIDO2 PREFERRED
###!    Proprietary TPM/TrustZone blobs are rejected.  External FIDO2/U2F
###!    hardware keys are the preferred root of trust.
###!
###! 8. SLOTS ARE EXAMPLES, NOT HARDCODED
###!    The production/guest/kitty slot mapping is documentation example.
###!    The Initrd Dispatcher module accepts any slot-to-generation mapping.
###!
###! 9. FUTURE: ZAPPIX + HARDWARE KEY INTEGRATION
###!    Hardware key and Zappix integration do not yet exist in a form
###!    acceptable for NiXium.  Expected future work includes: the agent
###!    refusing to serve secrets when Zappix reports stolen state, remote
###!    agent wipe via Zappix signal, and FIDO2-based agent unlock policies.
###! The agent socket protocol is designed to support these extensions
###!    without breaking the core interface.
###! ## Legacy Code
###!
###! This is the original agenix code which is kept for reference
###!
###! # {
###!   config,
###!   options,
###!   lib,
###!   pkgs,
###!   ...
###! }:
###! with lib; let
###!   cfg = config.age;
###!
###!   isDarwin = lib.attrsets.hasAttrByPath ["environment" "darwinConfig"] options;
###!
###!   ageBin = config.age.ageBin;
###!
###!   users = config.users.users;
###!
###!   mountCommand =
###!     if isDarwin
###!     then ''
###!       if ! diskutil info "${cfg.secretsMountPoint}" &> /dev/null; then
###!           num_sectors=1048576
###!           dev=$(hdiutil attach -nomount ram://"$num_sectors" | sed 's/[[:space:]]*$//')
###!           newfs_hfs -v agenix "$dev"
###!           mount -t hfs -o nobrowse,nodev,nosuid,-m=0751 "$dev" "${cfg.secretsMountPoint}"
###!       fi
###!     ''
###!     else ''
###!       grep -q "${cfg.secretsMountPoint} ramfs" /proc/mounts ||
###!         mount -t ramfs none "${cfg.secretsMountPoint}" -o nodev,nosuid,mode=0751
###!     '';
###!   newGeneration = ''
###!     _agenix_generation="$(basename "$(readlink ${cfg.secretsDir})" || echo 0)"
###!     (( ++_agenix_generation ))
###!     echo "[agenix] creating new generation in ${cfg.secretsMountPoint}/$_agenix_generation"
###!     mkdir -p "${cfg.secretsMountPoint}"
###!     chmod 0751 "${cfg.secretsMountPoint}"
###!     ${mountCommand}
###!     mkdir -p "${cfg.secretsMountPoint}/$_agenix_generation"
###!     chmod 0751 "${cfg.secretsMountPoint}/$_agenix_generation"
###!   '';
###!
###!   chownGroup =
###!     if isDarwin
###!     then "admin"
###!     else "keys";
###!   chownMountPoint = ''
###!     chown :${chownGroup} "${cfg.secretsMountPoint}" "${cfg.secretsMountPoint}/$_agenix_generation"
###!   '';
###!
###!   setTruePath = secretType: ''
###!     ${
###!       if secretType.symlink
###!       then ''
###!         _truePath="${cfg.secretsMountPoint}/$_agenix_generation/${secretType.name}"
###!       ''
###!       else ''
###!         _truePath="${secretType.path}"
###!       ''
###!     }
###!   '';
###!
###!   installSecret = secretType: ''
###!     ${setTruePath secretType}
###!     echo "decrypting '${secretType.file}' to '$_truePath'..."
###!     TMP_FILE="$_truePath.tmp"
###!
###!     IDENTITIES=()
###!     for identity in ${toString cfg.identityPaths}; do
###!       test -r "$identity" || continue
###!       test -s "$identity" || continue
###!       IDENTITIES+=(-i)
###!       IDENTITIES+=("$identity")
###!     done
###!
###!     test "''${#IDENTITIES[@]}" -eq 0 && echo "[agenix] WARNING: no readable identities found!"
###!
###!     mkdir -p "$(dirname "$_truePath")"
###!     [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && mkdir -p "$(dirname "${secretType.path}")"
###!     (
###!       umask u=r,g=,o=
###!       test -f "${secretType.file}" || echo '[agenix] WARNING: encrypted file ${secretType.file} does not exist!'
###!       test -d "$(dirname "$TMP_FILE")" || echo "[agenix] WARNING: $(dirname "$TMP_FILE") does not exist!"
###!       LANG=${config.i18n.defaultLocale or "C"} ${ageBin} --decrypt "''${IDENTITIES[@]}" -o "$TMP_FILE" "${secretType.file}"
###!     )
###!     chmod ${secretType.mode} "$TMP_FILE"
###!     mv -f "$TMP_FILE" "$_truePath"
###!
###!     ${optionalString secretType.symlink ''
###!       [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && ln -sfT "${cfg.secretsDir}/${secretType.name}" "${secretType.path}"
###!     ''}
###!   '';
###!
###!   testIdentities =
###!     map
###!     (path: ''
###!       test -f ${path} || echo '[agenix] WARNING: config.age.identityPaths entry ${path} not present!'
###!     '')
###!     cfg.identityPaths;
###!
###!   cleanupAndLink = ''
###!     _agenix_generation="$(basename "$(readlink ${cfg.secretsDir})" || echo 0)"
###!     (( ++_agenix_generation ))
###!     echo "[agenix] symlinking new secrets to ${cfg.secretsDir} (generation $_agenix_generation)..."
###!     ln -sfT "${cfg.secretsMountPoint}/$_agenix_generation" ${cfg.secretsDir}
###!
###!     (( _agenix_generation > 1 )) && {
###!     echo "[agenix] removing old secrets (generation $(( _agenix_generation - 1 )))..."
###!     rm -rf "${cfg.secretsMountPoint}/$(( _agenix_generation - 1 ))"
###!     }
###!   '';
###!
###!   installSecrets = builtins.concatStringsSep "\n" (
###!     ["echo '[agenix] decrypting secrets...'"]
###!     ++ testIdentities
###!     ++ (map installSecret (builtins.attrValues cfg.secrets))
###!     ++ [cleanupAndLink]
###!   );
###!
###!   chownSecret = secretType: ''
###!     ${setTruePath secretType}
###!     chown ${secretType.owner}:${secretType.group} "$_truePath"
###!   '';
###!
###!   chownSecrets = builtins.concatStringsSep "\n" (
###!     ["echo '[agenix] chowning...'"]
###!     ++ [chownMountPoint]
###!     ++ (map chownSecret (builtins.attrValues cfg.secrets))
###!   );
###!
###!   secretType = types.submodule ({config, ...}: {
###!     options = {
###!       name = mkOption {
###!         type = types.str;
###!         default = config._module.args.name;
###!         defaultText = literalExpression "config._module.args.name";
###!         description = ''
###!           Name of the file used in {option}`age.secretsDir`
###!         '';
###!       };
###!       file = mkOption {
###!         type = types.path;
###!         description = ''
###!           Age file the secret is loaded from.
###!         '';
###!       };
###!       path = mkOption {
###!         type = types.str;
###!         default = "${cfg.secretsDir}/${config.name}";
###!         defaultText = literalExpression ''
###!           "''${cfg.secretsDir}/''${config.name}"
###!         '';
###!         description = ''
###!           Path where the decrypted secret is installed.
###!         '';
###!       };
###!       mode = mkOption {
###!         type = types.str;
###!         default = "0400";
###!         description = ''
###!           Permissions mode of the decrypted secret in a format understood by chmod.
###!         '';
###!       };
###!       owner = mkOption {
###!         type = types.str;
###!         default = "0";
###!         description = ''
###!           User of the decrypted secret.
###!         '';
###!       };
###!       group = mkOption {
###!         type = types.str;
###!         default = users.${config.owner}.group or "0";
###!         defaultText = literalExpression ''
###!           users.''${config.owner}.group or "0"
###!         '';
###!         description = ''
###!           Group of the decrypted secret.
###!         '';
###!       };
###!       symlink = mkEnableOption "symlinking secrets to their destination" // {default = true;};
###!     };
###!   });
###! in {
###!   imports = [
###!     (mkRenamedOptionModule ["age" "sshKeyPaths"] ["age" "identityPaths"])
###!   ];
###!
###!   options.age = {
###!     ageBin = mkOption {
###!       type = types.str;
###!       default = "${pkgs.age}/bin/age";
###!       defaultText = literalExpression ''
###!         "''${pkgs.age}/bin/age"
###!       '';
###!       description = ''
###!         The age executable to use.
###!       '';
###!     };
###!     secrets = mkOption {
###!       type = types.attrsOf secretType;
###!       default = {};
###!       description = ''
###!         Attrset of secrets.
###!       '';
###!     };
###!     secretsDir = mkOption {
###!       type = types.path;
###!       default = "/run/agenix";
###!       description = ''
###!         Folder where secrets are symlinked to
###!       '';
###!     };
###!     secretsMountPoint = mkOption {
###!       type =
###!         types.addCheck types.str
###!         (s:
###!           (builtins.match "[ \t\n]*" s)
###!           == null # non-empty
###!           && (builtins.match ".+/" s) == null) # without trailing slash
###!         // {description = "${types.str.description} (with check: non-empty without trailing slash)";};
###!       default = "/run/agenix.d";
###!       description = ''
###!         Where secrets are created before they are symlinked to {option}`age.secretsDir`
###!       '';
###!     };
###!     identityPaths = mkOption {
###!       type = types.listOf types.path;
###!       default =
###!         if (config.services.openssh.enable or false)
###!         then map (e: e.path) (lib.filter (e: e.type == "rsa" || e.type == "ed25519") config.services.openssh.hostKeys)
###!         else if isDarwin
###!         then [
###!           "/etc/ssh/ssh_host_ed25519_key"
###!           "/etc/ssh/ssh_host_rsa_key"
###!         ]
###!         else [];
###!       defaultText = literalExpression ''
###!         if (config.services.openssh.enable or false)
###!         then map (e: e.path) (lib.filter (e: e.type == "rsa" || e.type == "ed25519") config.services.openssh.hostKeys)
###!         else if isDarwin
###!         then [
###!           "/etc/ssh/ssh_host_ed25519_key"
###!           "/etc/ssh/ssh_host_rsa_key"
###!         ]
###!         else [];
###!       '';
###!       description = ''
###!         Path to SSH keys to be used as identities in age decryption.
###!       '';
###!     };
###!   };
###!
###!   config = mkIf (cfg.secrets != {}) (mkMerge [
###!     {
###!       assertions = [
###!         {
###!           assertion = cfg.identityPaths != [];
###!           message = "age.identityPaths must be set.";
###!         }
###!       ];
###!     }
###!
###!     (optionalAttrs (!isDarwin) {
###!       system.activationScripts.agenixNewGeneration = {
###!         text = newGeneration;
###!         deps = [
###!           "specialfs"
###!         ];
###!       };
###!
###!       system.activationScripts.agenixInstall = {
###!         text = installSecrets;
###!         deps = [
###!           "agenixNewGeneration"
###!           "specialfs"
###!         ];
###!       };
###!
###!       system.activationScripts.users.deps = ["agenixInstall"];
###!
###!       system.activationScripts.agenixChown = {
###!         text = chownSecrets;
###!         deps = [
###!           "users"
###!           "groups"
###!         ];
###!       };
###!
###!       system.activationScripts.agenix = {
###!         text = "";
###!         deps = ["agenixChown"];
###!       };
###!     })
###!     (optionalAttrs isDarwin {
###!       launchd.daemons.activate-agenix = {
###!         script = ''
###!           set -e
###!           set -o pipefail
###!           export PATH="${pkgs.gnugrep}/bin:${pkgs.coreutils}/bin:@out@/sw/bin:/usr/bin:/bin:/usr/sbin:/sbin"
###!           ${newGeneration}
###!           ${installSecrets}
###!           ${chownSecrets}
###!           exit 0
###!         '';
###!         serviceConfig = {
###!           RunAtLoad = true;
###!           KeepAlive.SuccessfulExit = false;
###!         };
###!       };
###!     })
###!   ]);
###! }
