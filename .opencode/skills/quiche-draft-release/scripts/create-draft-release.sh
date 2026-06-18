#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage:
  create-draft-release.sh [options] <release-ref>

Creates a GitHub draft release for the quiche crate using either the commit
that bumped quiche/Cargo.toml, or an existing release tag pointing at that
commit. The tag does not need to exist yet; when it is missing, the release is
created with --target <release-commit>.

Options:
  --dry-run            Print inferred release metadata and the gh command.
  --notes-file PATH    Markdown notes file to use for the draft release.
  --repo OWNER/REPO    GitHub repository. Defaults to cloudflare/quiche.
  --title TITLE        Release title. Defaults to the inferred version.
  -h, --help           Show this help.
USAGE
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

quote_cmd() {
    local first=1

    for arg in "$@"; do
        if [ "$first" -eq 0 ]; then
            printf ' '
        fi

        first=0
        printf '%q' "$arg"
    done

    printf '\n'
}

version_from_commit() {
    local commit=$1

    git show "$commit:quiche/Cargo.toml" |
        awk -F '"' '/^version = / { print $2; exit }'
}

repo=cloudflare/quiche
dry_run=0
notes_file=
title=
release_ref=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            dry_run=1
            shift
            ;;

        --notes-file)
            [ "$#" -ge 2 ] || die '--notes-file requires a path'
            notes_file=$2
            shift 2
            ;;

        --repo)
            [ "$#" -ge 2 ] || die '--repo requires OWNER/REPO'
            repo=$2
            shift 2
            ;;

        --title)
            [ "$#" -ge 2 ] || die '--title requires a value'
            title=$2
            shift 2
            ;;

        -h|--help)
            usage
            exit 0
            ;;

        --)
            shift
            break
            ;;

        -*)
            die "unknown option: $1"
            ;;

        *)
            [ -z "$release_ref" ] || die 'only one release ref is supported'
            release_ref=$1
            shift
            ;;
    esac
done

[ -n "$release_ref" ] || {
    usage >&2
    exit 2
}

command -v git >/dev/null 2>&1 || die 'git is required'
command -v gh >/dev/null 2>&1 || die 'GitHub CLI (gh) is required'

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) ||
    die 'must be run from inside the quiche git repository'
cd "$repo_root"

input_tag=
if git rev-parse -q --verify "refs/tags/$release_ref" >/dev/null; then
    input_tag=$release_ref
elif [[ "$release_ref" == refs/tags/* ]] &&
    git rev-parse -q --verify "$release_ref" >/dev/null
then
    input_tag=${release_ref#refs/tags/}
fi

commit=$(git rev-parse --verify "$release_ref^{commit}" 2>/dev/null) ||
    die "not a commit or tag: $release_ref"

version=$(version_from_commit "$commit")
[ -n "$version" ] ||
    die "could not read version from quiche/Cargo.toml at $commit"

if [ -n "$input_tag" ] && [ "$input_tag" != "$version" ]; then
    die "input tag $input_tag does not match quiche version $version"
fi

parent=$(git rev-parse --verify "$commit^" 2>/dev/null || true)
if [ -n "$parent" ]; then
    previous_version=$(version_from_commit "$parent" || true)

    if [ "$previous_version" = "$version" ]; then
        die "commit $commit does not bump quiche/Cargo.toml version"
    fi
fi

previous_tag=
while IFS= read -r tag; do
    [ "$tag" != "$version" ] || continue

    previous_tag=$tag
    break
done < <(
    git tag --merged "$commit" \
        --sort=-version:refname \
        --list '[0-9]*.[0-9]*.[0-9]*'
)

[ -n "$previous_tag" ] ||
    die "could not infer previous quiche release tag before $version"

compare_url="https://github.com/$repo/compare/$previous_tag...$version"
title=${title:-$version}

tag_exists=0
target_args=()
if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
    tag_exists=1
    tag_commit=$(git rev-list -n 1 "$version")

    if [ "$tag_commit" != "$commit" ]; then
        die "tag $version points to $tag_commit, not $commit"
    fi
else
    target_args=(--target "$commit")
fi

cmd=(
    gh release create "$version"
    --repo "$repo"
    --draft
    --title "$title"
)

if [ -n "$notes_file" ]; then
    cmd+=(--notes-file "$notes_file")
fi

cmd+=("${target_args[@]}")

if [ "$dry_run" -eq 1 ]; then
    cat <<EOF
release_ref=$release_ref
input_tag=$input_tag
release_commit=$commit
version=$version
previous_version=${previous_version:-}
previous_tag=$previous_tag
compare_url=$compare_url
tag_exists=$tag_exists
title=$title
notes_file=${notes_file:-}
EOF

    printf 'command='
    quote_cmd "${cmd[@]}"
    exit 0
fi

[ -n "$notes_file" ] || die '--notes-file is required when creating a release'
[ -f "$notes_file" ] || die "notes file not found: $notes_file"

if gh release view "$version" --repo "$repo" >/dev/null 2>&1; then
    die "GitHub release already exists for $version"
fi

"${cmd[@]}"

gh release view "$version" --repo "$repo" \
    --json tagName,name,isDraft,isPrerelease,url
