###! # AGE-HOME.NIX -- User-Level Secrets (NiXium maintainer fork)
###!
###! SUMMARY: Home-manager counterpart to age.nix.  Independent module for
###! user-level age secrets sharing the same design ideology (Ghost Identity,
###! HNDL resistance, persistent agent, direct pipe deployment, injection
###! model) but adapted for user context.  Identity derived from login
###! password via PAM (pam_agenix.so), optional FIDO2 hardware key for
###! bootstrap.  Per-user agent instances with sockets in XDG_RUNTIME_DIR.
###! Exit codes: 0=authentic, 1=missing, 2=degraded, 4=integrity violation.
###!
###! ## WHY THIS FILE EXISTS
###!
###! User-level secrets require a separate module because:
###!   - They are tied to USER identity, not machine identity.
###!   - The decryption key must be available AFTER login (not at boot).
###!   - Different users on the same machine must have isolated secrets.
###!   - Zero-trust model: admin does not have access to user keys by default.
###!
###! Secrets managed by this module:
###!   - User SSH private keys (~/.ssh/id_ed25519)
###!   - Application tokens (GitHub, GitLab, NixOS cache)
###!   - User-specific VPN credentials (WireGuard, OpenVPN)
###!   - Browser/email client passwords
###!   - GPG keys
###!
###! ## USER-LEVEL ARCHITECTURE
###!
###! ### Login Sequence
###!
###! 1. User authenticates (SDDM, GDM, tty, SSH, etc.).
###! 2. pam_agenix.so fires at pam_authenticate or pam_open_session.
###! 3. PAM captures password, derives IdentityKey (Ghost Identity pipeline).
###! 4. PAM starts per-user agenix-agent:
###!      agenix-agent serve --socket /run/user/UID/agenix.sock
###! 5. HM systemd --user starts (if not already running).
###! 6. Per-secret services call:
###!      agenix-agent get-secret <name> > $target_path
###!
###! ### Logout Sequence
###!
###! 1. User logs out (display manager closes session).
###! 2. systemd --user stops.
###! 3. agenix-agent receives SIGTERM, memset()s key buffer, exits.
###! 4. XDG_RUNTIME_DIR is cleaned up (socket removed automatically).
###!
###! ## GHOST IDENTITY (User-Level)
###!
###! Same pipeline as age.nix, adapted for user context:
###!
###!   PAM Hook                    user-salt.<name>.age
###!       |                              |
###!       v                              v
###!   Login Password --PAM--> BootstrapKey --Decrypt--> StableSalt
###!                                                            |
###!                                              Login Pass --+
###!                                                            v
###!                                              Argon2id --> IdentityKey
###!                                                            |
###!                                                            v
###!                                              agenix-agent (mlock, socket)
###!
###! ### Stage 1: Bootstrap (PAM)
###!   At login, pam_agenix.so captures the user's password.
###!   Derives BootstrapKey: Argon2id(password, salt=user-uuid) -> 32 bytes.
###!   The user's UUID is deterministic (derived from username + machine-id).
###!
###! ### Stage 2: Salt Recovery
###!   Reads user-salt.<username>.age from the Nix store.
###!   Decrypts: BootstrapKey -> user-salt.age -> StableSalt.
###!   Attacker with disk image cannot obtain StableSalt --
###!   user-salt.age is encrypted with the BootstrapKey.
###!
###! ### Stage 3: Identity Derivation
###!   Input: Login password + StableSalt.
###!   Process: Argon2id(password, salt=StableSalt) -> 32 bytes.
###!   Output: IdentityKey -- age-compatible X25519 private key.
###!   Piped into per-user agenix-agent via stdin.
###!
###! HNDL DEFENSE: Identical to age.nix.  Salt is encrypted, requiring two
###! KDF rounds to brute-force.  User secrets are HNDL-resistant regardless
###! of whether admin's keys are also compromised.
###!
###! ## AGENT ARCHITECTURE (User-Level)
###!
###! Each user has their own agenix-agent instance.  Identical to age.nix
###! agent architecture with different socket path.
###!
###! ### Lifecycle
###!
###! 1. LOGIN: PAM starts agent.  Receives IdentityKey on stdin.
###! 2. PERSIST: Agent mlock()s key, opens /run/user/UID/agenix.sock.
###! 3. ACTIVE: Per-secret --user services call get-secret via socket.
###! 4. LOGOUT: systemd --user stops.  Agent memset()s key, exits.
###! 5. CRASH: Agent crash does not affect already-deployed secrets.
###!
###! ### Socket
###!
###!   /run/user/UID/agenix.sock (mode 0600, user-owned)
###!   Protocol: get-secret <name>
###!   Response: Decrypted secret content on stdout
###!
###! ## BOOTSTRAP PROVIDERS (User-Level)
###!
###! ### auth.user.pam (default, always available)
###!   Captures login password via pam_agenix.so at authentication time.
###!   KDF: Argon2id (preferred) or PBKDF2 (option).
###!   No additional hardware required.
###!
###! ### auth.user.fido2 (optional)
###!   Uses FIDO2/U2F token's HMAC-SECRET to bind user identity
###!   to a physical hardware key.  Token must be present at login.
###!   Future: not yet implemented.
###!
###! ### auth.user.fingerprint (future)
###!   Uses fprintd to derive identity from a verified fingerprint.
###!   User-level only -- system-level fingerprint at boot is impractical.
###!
###! ## DIFFERENCES FROM AGE.NIX (SYSTEM MODULE)
###!
###! These are hard constraints, not shared architecture references:
###!
###!   FEATURE               SYSTEM (age.nix)             HM (age-home.nix)
###!   --------------------  ---------------------------  ---------------------
###!   Bootstrap provider    FIDO2 / boot passphrase      PAM / optional FIDO2
###!   Identity source       /run/agenix.sock              /run/user/UID/agenix.sock
###!   Agent lifecycle       Initrd -> shutdown            Login -> logout
###!   Service type          systemd system units          systemd --user units
###!   neededForBoot         Supported (activation)       Not applicable
###!   Generation dispatch   LUKS slot -> kexec           Not applicable
###!   Activation scripts   NewGen, Install, Chown        None
###!   Chown                Not needed (direct pipe)      Not needed
###!   Identity file        salt.age (machine)           user-salt.<name>.age
###!   Key lifecycle         Lost on shutdown            Lost on logout
###!   Zero-trust           N/A (admin has machine key)   Admin cannot decrypt
###!
###! ## EXIT CODES
###!
###! Identical semantics to age.nix:
###!
###!   0 -- Authentic (decrypted + check passed -> deployed).
###!   1 -- Missing (decrypt failed, no fallback).
###!   2 -- Degraded (decrypt failed, fallback script ran).
###!   4 -- Integrity violation (decrypted but check failed -- no fallback).
###!
###! ## EXECSTART PSEUDOCODE
###!
###! Identical to age.nix:
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
###! ## INJECTION MODEL
###!
###! Identical to age.nix.  Placeholder derived from check preset.
###! Override via age.secrets.<name>.placeholder for edge cases.
###!
###! ## PUBLIC API
###!
###! age.package (package, default=pkgs.rage)
###!   The age binary for user-level decryption.
###!
###! age.secrets.<name>.file (types.path, REQUIRED)
###!   .age-encrypted file path in the Nix store.
###!
###! age.secrets.<name>.path (str, default=$XDG_RUNTIME_DIR/agenix/<name>)
###!   Destination path for the decrypted secret.
###!
###! age.secrets.<name>.fallback (submodule)
###!   .enable (bool, default=false)
###!   .script (nullOr lines, default=null)
###!
###! age.secrets.<name>.check (nullOr str, default=null)
###!   Regex pattern or preset name.  Same presets as age.nix.
###!
###! age.secrets.<name>.inject (list of str, default=[])
###!   Configuration files to patch with the decrypted secret.
###!
###! age.secrets.<name>.placeholder (nullOr str, default=null)
###!   Override automatic placeholder derivation.
###!
###! age.secrets.<name>.mode (str, default="0400")
###! age.secrets.<name>.symlink (bool -- removed, no /run/agenix)
###! age.secrets.<name>.after (list of str, default=[])
###!
###! age.secretsDir -- REMOVED (no /run/agenix ramfs)
###! age.secretsMountPoint -- REMOVED
###!
###! REMOVED: identityPaths -- sole identity is agent-held IdentityKey.
###!
###! ## KEY DESIGN DECISIONS
###!
###! 1. ZERO-TRUST FOR ADMIN
###!    User secrets are encrypted to the USER's public key only.
###!    Admin cannot decrypt user secrets at build time or runtime.
###!    agenix check skips user secrets unless admin's key is listed.
###!
###! 2. SINGLE SERVICE PER SECRET
###!    Same as age.nix.  Per-secret service handles decrypt, check,
###!    inject, and fallback in one ExecStart.
###!
###! 3. AGENT PER-USER
###!    Each user has their own agenix-agent instance, started by PAM
###!    at login.  Agent holds the user's IdentityKey, isolated from
###!    other users and from the system agent.
###!
###! 4. INJECT PLACEHOLDER FROM CHECK
###!    Same as age.nix.  Auto-derived from check preset.
###!
###! 5. NO /run/agenix RAMFS
###!    Same as age.nix.  Secrets go directly to target paths.
###!
###! ## IMPLEMENTATION STATUS
###!
###! [SPEC]   age-home.nix doc-comment block      DONE
###! [CODE]   age-home.nix module rewrite         PENDING
###! [CODE]   pam_agenix.so module                PENDING
###! [CODE]   agenix-agent per-user instance      PENDING
###! [CODE]   auth.user.pam provider              PENDING
###! [CODE]   auth.user.fido2 provider            PENDING
###! [CODE]   auth.user.fingerprint provider      FUTURE
###! [CODE]   Identity: user-salt.age generation  PENDING
###! [TEST]   HM service integration              PENDING
###!
###! ## Legacy Code
###!
###! This is the original agenix code which is kept for reference
###!
###!     {
###!       config,
###!       options,
###!       lib,
###!       pkgs,
###!       ...
###!     }:
###!     with lib; let
###!       cfg = config.age;
###!
###!       ageBin = lib.getExe config.age.package;
###!
###!       newGeneration = ''
###!         _agenix_generation="$(basename "$(readlink "${cfg.secretsDir}")" || echo 0)"
###!         (( ++_agenix_generation ))
###!         echo "[agenix] creating new generation in ${cfg.secretsMountPoint}/$_agenix_generation"
###!         mkdir -p "${cfg.secretsMountPoint}"
###!         chmod 0751 "${cfg.secretsMountPoint}"
###!         mkdir -p "${cfg.secretsMountPoint}/$_agenix_generation"
###!         chmod 0751 "${cfg.secretsMountPoint}/$_agenix_generation"
###!       '';
###!
###!       setTruePath = secretType: ''
###!         ${
###!           if secretType.symlink
###!           then ''
###!             _truePath="${cfg.secretsMountPoint}/$_agenix_generation/${secretType.name}"
###!           ''
###!           else ''
###!             _truePath="${secretType.path}"
###!           ''
###!         }
###!       '';
###!
###!       installSecret = secretType: ''
###!         ${setTruePath secretType}
###!         echo "decrypting '${secretType.file}' to '$_truePath'..."
###!         TMP_FILE="$_truePath.tmp"
###!
###!         IDENTITIES=()
###!         # shellcheck disable=2043
###!         for identity in ${toString cfg.identityPaths}; do
###!           test -r "$identity" || continue
###!           IDENTITIES+=(-i)
###!           IDENTITIES+=("$identity")
###!         done
###!
###!         test "''${#IDENTITIES[@]}" -eq 0 && echo "[agenix] WARNING: no readable identities found!"
###!
###!         mkdir -p "$(dirname "$_truePath")"
###!         # shellcheck disable=SC2193,SC2050
###!         [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && mkdir -p "$(dirname "${secretType.path}")"
###!         (
###!           umask u=r,g=,o=
###!           test -f "${secretType.file}" || echo '[agenix] WARNING: encrypted file ${secretType.file} does not exist!'
###!           test -d "$(dirname "$TMP_FILE")" || echo "[agenix] WARNING: $(dirname "$TMP_FILE") does not exist!"
###!           LANG=${config.i18n.defaultLocale or "C"} ${ageBin} --decrypt "''${IDENTITIES[@]}" -o "$TMP_FILE" "${secretType.file}"
###!         )
###!         chmod ${secretType.mode} "$TMP_FILE"
###!         mv -f "$TMP_FILE" "$_truePath"
###!
###!         ${optionalString secretType.symlink ''
###!           # shellcheck disable=SC2193,SC2050
###!           [ "${secretType.path}" != "${cfg.secretsDir}/${secretType.name}" ] && ln -sfT "${cfg.secretsDir}/${secretType.name}" "${secretType.path}"
###!         ''}
###!       '';
###!
###!       testIdentities =
###!         map
###!         (path: ''
###!           test -f ${path} || echo '[agenix] WARNING: config.age.identityPaths entry ${path} not present!'
###!         '')
###!         cfg.identityPaths;
###!
###!       cleanupAndLink = ''
###!         _agenix_generation="$(basename "$(readlink "${cfg.secretsDir}")" || echo 0)"
###!         (( ++_agenix_generation ))
###!         echo "[agenix] symlinking new secrets to ${cfg.secretsDir} (generation $_agenix_generation)..."
###!         ln -sfT "${cfg.secretsMountPoint}/$_agenix_generation" "${cfg.secretsDir}"
###!
###!         (( _agenix_generation > 1 )) && {
###!         echo "[agenix] removing old secrets (generation $(( _agenix_generation - 1 )))..."
###!         rm -rf "${cfg.secretsMountPoint}/$(( _agenix_generation - 1 ))"
###!         }
###!       '';
###!
###!       installSecrets = builtins.concatStringsSep "\n" (
###!         ["echo '[agenix] decrypting secrets...'"]
###!         ++ testIdentities
###!         ++ (map installSecret (builtins.attrValues cfg.secrets))
###!         ++ [cleanupAndLink]
###!       );
###!
###!       secretType = types.submodule ({
###!         config,
###!         name,
###!         ...
###!       }: {
###!         options = {
###!           name = mkOption {
###!             type = types.str;
###!             default = name;
###!             description = ''
###!               Name of the file used in ''${cfg.secretsDir}
###!             '';
###!           };
###!           file = mkOption {
###!             type = types.path;
###!             description = ''
###!               Age file the secret is loaded from.
###!             '';
###!           };
###!           path = mkOption {
###!             type = types.str;
###!             default = "${cfg.secretsDir}/${config.name}";
###!             description = ''
###!               Path where the decrypted secret is installed.
###!             '';
###!           };
###!           mode = mkOption {
###!             type = types.str;
###!             default = "0400";
###!             description = ''
###!               Permissions mode of the decrypted secret in a format understood by chmod.
###!             '';
###!           };
###!           symlink = mkEnableOption "symlinking secrets to their destination" // {default = true;};
###!         };
###!       });
###!
###!       mountingScript = let
###!         app = pkgs.writeShellApplication {
###!           name = "agenix-home-manager-mount-secrets";
###!           runtimeInputs = with pkgs; [coreutils];
###!           text = ''
###!             ${newGeneration}
###!             ${installSecrets}
###!             exit 0
###!           '';
###!         };
###!       in
###!         lib.getExe app;
###!
###!       userDirectory = dir: let
###!         inherit (pkgs.stdenv.hostPlatform) isDarwin;
###!         baseDir =
###!           if isDarwin
###!           then "$(getconf DARWIN_USER_TEMP_DIR)"
###!           else "\${XDG_RUNTIME_DIR}";
###!       in "${baseDir}/${dir}";
###!
###!       userDirectoryDescription = dir:
###!         literalExpression ''
###!           "${XDG_RUNTIME_DIR}"/${dir} on linux or "$(getconf DARWIN_USER_TEMP_DIR)"/${dir} on darwin.
###!         '';
###!     in {
###!       options.age = {
###!         package = mkPackageOption pkgs "age" {};
###!
###!         secrets = mkOption {
###!           type = types.attrsOf secretType;
###!           default = {};
###!           description = ''
###!             Attrset of secrets.
###!           '';
###!         };
###!
###!         identityPaths = mkOption {
###!           type = types.listOf types.path;
###!           default = [
###!             "${config.home.homeDirectory}/.ssh/id_ed25519"
###!             "${config.home.homeDirectory}/.ssh/id_rsa"
###!           ];
###!           defaultText = literalExpression ''
###!             [
###!               "''${config.home.homeDirectory}/.ssh/id_ed25519"
###!               "''${config.home.homeDirectory}/.ssh/id_rsa"
###!             ]
###!           '';
###!           description = ''
###!             Path to SSH keys to be used as identities in age decryption.
###!           '';
###!         };
###!
###!         secretsDir = mkOption {
###!           type = types.str;
###!           default = userDirectory "agenix";
###!           defaultText = userDirectoryDescription "agenix";
###!           description = ''
###!             Folder where secrets are symlinked to
###!           '';
###!         };
###!
###!         secretsMountPoint = mkOption {
###!           default = userDirectory "agenix.d";
###!           defaultText = userDirectoryDescription "agenix.d";
###!           description = ''
###!             Where secrets are created before they are symlinked to ''${cfg.secretsDir}
###!           '';
###!         };
###!       };
###!
###!       config = mkIf (cfg.secrets != {}) {
###!         assertions = [
###!           {
###!             assertion = cfg.identityPaths != [];
###!             message = "age.identityPaths must be set.";
###!           }
###!         ];
###!
###!         systemd.user.services.agenix = lib.mkIf pkgs.stdenv.hostPlatform.isLinux {
###!           Unit = {
###!             Description = "agenix activation";
###!           };
###!           Service = {
###!             Type = "oneshot";
###!             ExecStart = mountingScript;
###!           };
###!           Install.WantedBy = ["default.target"];
###!         };
###!
###!         launchd.agents.activate-agenix = {
###!           enable = true;
###!           config = {
###!             ProgramArguments = [mountingScript];
###!             KeepAlive = {
###!               Crashed = false;
###!               SuccessfulExit = false;
###!             };
###!             RunAtLoad = true;
###!             ProcessType = "Background";
###!             StandardOutPath = "${config.home.homeDirectory}/Library/Logs/agenix/stdout";
###!             StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/agenix/stderr";
###!           };
###!         };
###!       };
###!     }
###!
