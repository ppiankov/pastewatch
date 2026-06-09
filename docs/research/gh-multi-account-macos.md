# Research: gh CLI Multi-Account on macOS

Checked: 2026-06-09

Verdict: directory-scoped configuration is useful, but it is not a complete
account-isolation boundary for GitHub CLI on macOS. For account-sensitive work,
the process must prove that it is using the intended account before it performs
the action.

## Public Evidence

- GitHub CLI issue
  [#12885](https://github.com/cli/cli/issues/12885), "Keychain lookup ignores
  account field, breaks multi-account setups", was open when checked on
  2026-06-09. The report describes a same-host, multi-account setup where
  config-directory selection points at one account, while token retrieval can
  resolve a different macOS Keychain entry because the lookup is keyed too
  broadly.
- The direnv homepage describes direnv as a shell extension that can load and
  unload environment variables depending on the current directory, by running a
  directory environment file in a subshell and exporting the resulting
  environment diff back to the active shell:
  <https://direnv.net/>.
- Ken Powers' "Quick Tip: Multiple User Configs with Git" is useful only as an
  example of directory-scoped Git identity with direnv:
  <https://knpw.rs/blg/multiple-git-users/>. It should not be treated as a
  GitHub CLI keychain workaround.

## Failure Mode

Manual active-account switching is shared mutable state. It may look fine in a
single terminal, but concurrent shells, background scripts, editor integrations,
and automation can observe or mutate different state than the shell the user is
watching.

Separate GitHub CLI config directories can reduce accidental cross-talk in file
configuration, but they do not prove token isolation on macOS. Issue #12885
describes a case where the selected config directory and the selected keychain
credential diverge. In that state, a status command can appear to identify one
account while an API call uses a token for another account.

The practical risk is not that every multi-account setup is broken. The risk is
that the config directory is weaker evidence than it appears to be when token
lookup passes through a shared macOS credential store.

## Environment Boundary

GitHub CLI documents `GH_TOKEN` and `GITHUB_TOKEN`, in that order, as
environment-provided tokens for commands targeting github.com, and says they
take precedence over stored credentials. That makes process environment a
stronger boundary than manual active-account switching: a child process can be
given the intended token explicitly.

That boundary must be handled as a secret boundary. Do not print token values,
enable shell tracing around token assignment, write generated environment files
to logs, or let CI echo command lines that contain credentials. The intended
invariant is:

1. Each identity resolves to the intended token before command execution.
2. The token is present only in the process environment that needs it.
3. A non-secret verification command proves the active login before
   account-sensitive work, for example:

   ```bash
   gh api user --jq .login
   ```

The verification output proves account selection. The token itself must never
be printed.

## Direnv Gotchas

Direnv can make directory-scoped environment selection ergonomic, but it is not
a credential isolation system by itself.

- Nested environment files do not compose automatically. If a lower directory
  needs parent settings, the lower file must explicitly source the parent
  behavior.
- Direnv shell hooks run in interactive prompt flows. Non-interactive scripts,
  subprocesses launched by editors, and automation may not inherit the same
  environment unless they are started from a shell where direnv has already
  exported it.
- Automation should pass the intended environment explicitly instead of relying
  on an operator's current shell directory or active account.

## Pastewatch Boundary

Pastewatch protects the before-paste path: content about to be pasted is scanned
before it reaches a target. Startup sweep behavior expands visibility to
pre-existing credential candidates in shell and config startup files, but it
does not turn account switching into an authorization boundary.

For GitHub CLI multi-account workflows, pastewatch should be treated as a guard
against leaking credential material, not as proof that the right account is
active. The proof remains the per-process environment invariant and the
non-secret login verification command.

## Publication

This note is an internal project research note. No external publication is
warranted unless there is a narrower public advisory to write after the upstream
GitHub CLI issue is resolved.
