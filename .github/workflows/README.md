# GitHub Actions Workflows

This directory holds Pelican's CI, testing, and release workflows. This README gives an overview of how they fit together and what repository configuration they depend on. Details belong in the comments at the top of each workflow.

## Vocabulary

- **Semver tag:** A Git tag such as `v7.27.0` or `v26.0.0-rc.3` that marks a release or release candidate.
- **Release images:** The container images that Pelican ships: `client`, `director`, `registry`, `origin`, `cache`, and their `osdf-*` variants.
- **Test image:** The `pelican-test` container image, in which the Linux tests run.
- **Promotion:** Copying a semver tag's release images from the private image repo to the public one, after approval.
- **Floating tags:** Mutable image tags, such as `v26.0` and `v26.x`, that move to newer releases over time.

## Conventions

- Workflows default to `permissions: contents: read` and grant more only per job.
- Third-party actions are pinned by commit SHA, with the version in a trailing comment.

## Container images

Images are built by `build-and-test.yml` from `images/Dockerfile` using `images/docker-bake.hcl`. Each architecture is built on its own runner, and the per-arch images are then combined into multi-arch manifests. The registry is OSG's Harbor instance at [hub.osg-htc.org](https://hub.osg-htc.org).

| Event          | Images pushed                  | Repo               | Tags                                 |
| -------------- | ------------------------------ | ------------------ | ------------------------------------ |
| Pull request   | none                           | n/a                | n/a                                  |
| Push to `main` | `pelican-dev`, `pelican-test`  | `pelican_platform` | `latest-itb`, `sha-<sha>`, timestamp |
| Semver tag     | release images, `pelican-test` | `pelican_private`  | `<tag>`, `sha-<sha>`, timestamp      |
| Promotion      | release images                 | `pelican_platform` | `<tag>`, plus floating tags          |

The PR, scheduled, and coverage workflows test against `pelican_platform/pelican-test:latest-itb`, the image from the most recent push to `main`.

Images built off of a semver tag stay private until someone promotes them with `promote-images.yml`. Promotion also applies the floating tags (see `.github/scripts/container-images/floating_image_tags.py`), computed against the tags already in `pelican_platform`:

- `latest` tracks the highest release before v26.
- From v26 on, `vN.0` tracks the highest `vN.0.z`, and `vN.x` tracks the highest `vN.y.z` with `y >= 1` (`x` being a literal, here).

## GitHub releases

On a semver tag, `release.yml` runs GoReleaser (configured by `.goreleaser.in.yml`), which creates a draft GitHub release, flagged as a pre-release, with the binaries, archives, packages, and checksums. Drafts are visible only to users with write access to the repo, and remain editable until published.

`post-release.yml` runs on the `released` event: when a release is published as a full release, or when a published pre-release is changed to one. It does not run for drafts or pre-releases.

## Cutting a release

1. Push a semver tag. `build-and-test.yml`, `release.yml`, and the macOS and Windows tests run.
1. Once they pass, review the draft release. Publish it, either as a pre-release (for an RC to be shared) or as a full release.
1. Run "Promote Container Images" with the tag. A reviewer for the `image-promotion` environment must approve the run.

For a tag cut only for testing, only step 1 is necessary.

## Required repository configuration

Credentials for pushing images are environment secrets, so that only the jobs that push can read them. Each environment's deployment branch or tag policy is what restricts its credentials to the intended refs, so those policies are part of the security model, not just hygiene.

| Environment       | Used by                              | Deployment refs | Contents                                                                                 |
| ----------------- | ------------------------------------ | --------------- | ---------------------------------------------------------------------------------------- |
| `harbor-main`     | `build-and-test.yml`, push to `main` | branch `main`   | `PELICAN_HARBOR_ROBOT_*`: pull and push on `pelican_platform`                            |
| `harbor-tags`     | `build-and-test.yml`, semver tag     | semver tags     | `PELICAN_HARBOR_ROBOT_*`: pull and push on `pelican_private`                             |
| `image-promotion` | `promote-images.yml`, `approve` job  | branch `main`   | Required reviewers; no secrets                                                           |
| `harbor-promote`  | `promote-images.yml`, `promote` job  | branch `main`   | `PELICAN_HARBOR_ROBOT_*`: pull on `pelican_private`, pull and push on `pelican_platform` |

`PELICAN_HARBOR_ROBOT_*` means the pair `PELICAN_HARBOR_ROBOT_USER` and `PELICAN_HARBOR_ROBOT_PASSWORD`. The `harbor-promote` credentials must be a single account, because Docker keeps only one credential per registry host.

Repository secrets:

- `PELICAN_HARBOR_PULL_USER` and `PELICAN_HARBOR_PULL_PASSWORD`: pull-only access to `pelican_private`, so that the Linux tests can pull the `pelican-test` image for a semver tag.

The push credentials must not also be available as repository or organization secrets, or any job could read them.

## Forks

Forks listed in `build-and-test.yml` can push images built off of semver tags to their own registry. See "Pull Requests that Modify Pelican's Dependencies" in [CONTRIBUTE.md](../../CONTRIBUTE.md#pull-requests-that-modify-pelicans-dependencies) for the setup.
