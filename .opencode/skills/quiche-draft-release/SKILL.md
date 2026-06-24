---
name: quiche-draft-release
description: quiche draft GitHub release automation from a release commit hash or existing tag. Use when creating draft releases for the quiche crate from a quiche/Cargo.toml version bump.
---

# quiche Draft Release

Use this skill when the user asks to create a GitHub draft release for the
`quiche` crate and provides, or should provide, either the commit hash that
bumped `quiche/Cargo.toml` or an existing release tag pointing at that commit.

Do not require a pre-existing tag. quiche release tags are created after the
release PR is merged, because GitHub does not support fast-forward PR merges.
Use the release commit hash as the source of truth when the tag does not exist
yet, and let `gh release create` target that commit. If the release tag already
exists, the user may provide either the tag or the commit hash.

## Inputs

- Required: a release ref. This is either a commit hash for the commit that
  changed `quiche/Cargo.toml` to the released version, or an existing quiche
  release tag such as `0.29.1` that points at that commit.
- Optional: a release title emoji. If none is requested, choose one consistent
  with existing quiche releases.

If the release ref is missing or ambiguous, ask one short clarification question.

## Workflow

1. Run a dry run with the helper script:

   ```bash
   ./.opencode/skills/quiche-draft-release/scripts/create-draft-release.sh --dry-run <release-ref>
   ```

2. Use the dry-run output to identify the version, previous quiche release tag,
   compare range, and whether the tag already exists.

3. Prepare release notes for `quiche/` only, following `RELEASING.md`:

   - Do not use a raw commit list.
   - Include only important user-visible changes.
   - Clearly mark breaking changes and security fixes.
   - Explain what applications need to change for breaking changes.
   - Use versioned `docs.rs` links for new public APIs where useful.
   - Ignore unrelated workspace crates, release commits, formatting, clippy,
     test-only changes, and internal refactors unless user-visible.

4. Write the release notes to a temporary file, for example:

   ```bash
   /tmp/opencode/quiche-release-<version>.md
   ```

5. Before creating the release, unless the user has explicitly asked to proceed
   without confirmation, show the exact `gh release create` command and ask for
   confirmation.

6. Create the GitHub draft release with the helper script:

   ```bash
   ./.opencode/skills/quiche-draft-release/scripts/create-draft-release.sh \
     --title "<emoji> <version>" \
     --notes-file /tmp/opencode/quiche-release-<version>.md \
     <release-ref>
   ```

7. Verify the draft after creation:

   ```bash
   gh release view <version> --repo cloudflare/quiche \
     --json tagName,name,isDraft,isPrerelease,url
   ```

GitHub draft release URLs often use `untagged-*`. Trust `tagName` from
`gh release view` to verify the draft is associated with the expected version.

## Helper Script Behavior

The helper script:

- Resolves the supplied release ref to a commit. The ref may be a commit hash or
  an existing quiche release tag.
- Reads the release version from `quiche/Cargo.toml` at the resolved commit.
- Verifies the resolved commit changed the quiche crate version relative to its
  first parent.
- Infers the previous quiche release tag from semver-like quiche tags merged
  into the release commit.
- Refuses to create a release if a GitHub release for that version already
  exists.
- Uses the existing release tag if it exists and points at the resolved commit.
- Adds `--target <commit>` when the tag does not exist yet.
- Creates the GitHub release as a draft only.

## Examples

Dry run:

```bash
./.opencode/skills/quiche-draft-release/scripts/create-draft-release.sh \
  --dry-run f0c7193c3
```

Dry run with an existing tag:

```bash
./.opencode/skills/quiche-draft-release/scripts/create-draft-release.sh \
  --dry-run 0.29.1
```

Create a draft release:

```bash
./.opencode/skills/quiche-draft-release/scripts/create-draft-release.sh \
  --title "🩹 0.29.1" \
  --notes-file /tmp/opencode/quiche-release-0.29.1.md \
  f0c7193c3
```

Create a draft release from an existing tag:

```bash
./.opencode/skills/quiche-draft-release/scripts/create-draft-release.sh \
  --title "🩹 0.29.1" \
  --notes-file /tmp/opencode/quiche-release-0.29.1.md \
  0.29.1
```

## Do Not

- Do not create or move git tags manually as part of this skill.
- Do not publish the release; keep it as a draft.
- Do not create releases for non-`quiche` workspace crates with this skill.
- Do not overwrite or edit an existing GitHub release unless the user explicitly
  asks for that.
