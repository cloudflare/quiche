Releasing
=========

This document describes the process for cutting releases of the crates in this
repository.

Major, Minor and Patch releases
-------------------------------

Before cutting a release it's important to decide whether a major or minor
release needs to be created. This is important because creating major
(incompatible) releases requires work in the dependent projects, while minor
releases don't, so we should avoid creating unnecessary work for users by using
the correct release type.

All crates in this repository currently use pre-1.0 version numbers, meaning
that bumping the minor component (the `Y` in `X.Y.Z`) is equivalent to doing a
major release, while bumping the patch component (`Z`) is equivalent to a minor
release.

In order to determine whether a major or minor release is necessary, the
[cargo-semver-checks](https://crates.io/crates/cargo-semver-checks) tool can be
used to detect API-breaking changes:

```
 $ cargo semver-checks -p <crate>
```

However sometimes a major release needs to be cut even if semver-checks doesn't
detect an API change, for example in case of major behaviour changes in the
crate that might affect applications using it.

Checking dependencies
---------------------

It's also important to ensure the crate to be released can be built outside of
the repository, meaning that all required dependencies have also been released
and published already, otherwise there is a risk of cutting a release that can't
then be published to crates.io:

```
 $ cargo package -p <crate>
```

Creating a release
------------------

A release can now be created using the `cargo release` command:

```
 $ git checkout -b release-x.y.z
 $ cargo release --no-push --no-publish --no-tag -x <patch|minor> -p <crate>
```

The `release-x.y.z` branch can then be pushed to GitHub and a pull request
opened.

Note that because GitHub will rebase the release commit on merging the PR, we
use the `--no-tag` option to avoid tagging the release at this point. The tag
should only be created once the release PR is merged as follows:

```
 $ git tag <crate>-<version>
```

e.g. `git tag tokio-quiche-0.6.0`.

For historical reasons, releases of quiche itself do not have the name of the
crate in the tag (so would only be `0.6.0` in the example above).

Publishing the release
----------------------

Finally, the new release needs to be published to crates.io:

```
 $ cargo publish -p <crate>
```

It's good practice to check that the release then gets successfully published on
[crates.io](https://crates.io/) and that the documentation is correctly built
and published to [docs.rs](https://docs.rs) (this might take a few minutes), in
case bad changes slipped through the process and caused the crate to not be
published correctly.

Release notes
-------------

We currently only provide release notes for the quiche crate itself, via GitHub
releases https://github.com/cloudflare/quiche/releases

Release notes should not use the raw list of git commits, as that usually
includes a number of commits that don't really need to appear in the notes as
they are not useful for users to know (e.g. internal refactoring, test fixes,
warnings/clippy/formatting fixes, ...), and commit messages alone aren't
necessarily understandble by users of quiche anyway.

Only the more important *user visible* changes should be listed, with a brief
description of the change and potentially links to docs.rs (e.g. for new APIs).

Additionally, breaking changes and security fixes should be clearly marked as
such as they are generally the ones that most require users' attention (see e.g.
[this one](https://github.com/cloudflare/quiche/releases/tag/0.24.0) for breaking
changes, and [this one](https://github.com/cloudflare/quiche/releases/tag/0.24.4)
for security fixes, or look for "breaking changes" and "security" in the list
of releases linked above).

It's especially important to note what changes an application might need to do
in case of breaking changes, so that users can more easily take action.

The emoji in the release name is optional, but it's the only thing close to
"fun" when doing a release. You can pick one randomly or one that is related
in one way or another to the contents of the release.

Don't forget to pick the appropriate tag for the release in the dropdown menu,
as well as marking the new release as the latest one.
