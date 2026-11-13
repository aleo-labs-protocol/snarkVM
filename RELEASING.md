# Releasing

snarkVM releases are crates.io first. Merging a workspace version-bump PR into `staging` runs `.github/workflows/publish-crates.yml`, publishes unpublished lockstep snarkVM crate versions to crates.io, and creates one GitHub tag and release named `v{version}` from the umbrella `snarkvm` crate.

Do not publish normal releases with manual `cargo publish`. The workflow uses crates.io Trusted Publishing through GitHub OIDC, so it does not require a long-lived crates.io token.

This flow is based on ProvableHQ/leo's release-plz publishing flow, with Leo's binary release artifact dispatch removed.

## Normal Release Flow

1. Open a PR that bumps the workspace version across all lockstep snarkVM crates.
2. Confirm the version bump is consistent across the lockstep crate set.
3. Merge the PR to `staging`.
4. Let `.github/workflows/publish-crates.yml` publish the crates and create the single `v{version}` tag and GitHub release.

The `snarkvm-testchain-generator` binary helper is not part of the lockstep release set.

## Dry Run

Use the Actions tab to run `Publish Crates` manually with `dry_run` set to `true`.

The dry run checks what release-plz would publish and reports the planned single tag without publishing crates, creating tags, or creating GitHub releases.

## Trusted Publishing Setup

Trusted Publishing is a one-time crates.io setup for each published crate. Configure it for `snarkvm` and each already-published `snarkvm-*` crate:

1. Open the crate on crates.io.
2. Go to Settings, then Trusted Publishing.
3. Select Add.
4. Set Owner to `ProvableHQ`.
5. Set Repository to `snarkVM`.
6. Set Workflow filename to `publish-crates.yml`.
7. Leave Environment blank.

This setup is inherently per crate and should be scripted across the crate set. It does not mean release-plz creates per-crate tags at release time; `release-plz.toml` keeps GitHub tags and releases on the umbrella `snarkvm` crate only.

## Tag Collisions

`release-plz release` treats an existing `v{version}` git tag as already released and will skip publishing the umbrella `snarkvm` crate and creating its release for that version, even if crates.io has not yet received it. Before enabling this flow, make sure the next workspace version does not already have a matching upstream tag. If a stale or pre-created `v{version}` tag exists for a version that was never published, remove or migrate it first.

## New Crate Bootstrap

Trusted Publishing cannot reserve a brand-new crate name. A new `snarkvm-*` crate needs one initial manual `cargo publish` with a crates.io token before Trusted Publishing can be enabled for that crate.

After the first publish and Trusted Publishing setup, the normal workflow takes over for later versions.
