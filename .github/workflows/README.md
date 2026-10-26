# GitHub Actions Workflows

This directory holds Pelican's CI, testing, and release workflows. This README gives an overview of how they fit together and what repository configuration they depend on. Details belong in the comments at the top of each workflow.

## Vocabulary

- **Semver tag:** A Git tag, such as `v7.27.0` or `v26.0.0-rc.3`, that marks a release or release candidate.
- **Release images:** The container images that Pelican ships: `client`, `director`, `registry`, `origin`, `cache`, and their `osdf-*` variants.
- **Test image:** The `pelican-test` container image, in which the Linux tests run.
- **CI repo:** The image repo that automated builds push to, both off of `main` and off of semver tags. Its contents reflect what CI last built, not what anyone approved.
- **Release repo:** The image repo for published images. Images reach it only through promotion, so everything in it was approved by a person.
- **Promotion:** Copying a semver tag's release images from the CI repo to the release repo, after approval.
- **Floating tags:** Mutable image tags, such as `v26.0` and `v26.x`, that move to newer releases over time.

## Conventions

- Workflows default to `permissions: contents: read` and grant more only per job.
- Third-party actions are pinned by commit SHA, with the version in a trailing comment.

## Container images

Images are built by `build-and-test.yml` from `images/Dockerfile` using `images/docker-bake.hcl`. Each architecture is built on its own runner, and the per-arch images are then combined into multi-arch manifests. The registry is OSG's Harbor instance at [hub.osg-htc.org](https://hub.osg-htc.org). The CI and release repos, and the list of release images are defined in `.github/scripts/container-images/config.sh`.

| Event          | Images pushed                  | Repo               | Tags                                 |
| -------------- | ------------------------------ | ------------------ | ------------------------------------ |
| Pull request   | none                           | n/a                | n/a                                  |
| Push to `main` | `pelican-dev`, `pelican-test`  | `pelican-ci`       | `latest-itb`, `sha-<sha>`, timestamp |
| Semver tag     | release images, `pelican-test` | `pelican-ci`       | `<tag>`, `sha-<sha>`, timestamp      |
| Promotion      | release images                 | `pelican_platform` | `<tag>`, plus floating tags          |

The PR, scheduled, and coverage workflows test against `pelican-ci/pelican-test:latest-itb`, the image from the most recent push to `main`.

Images built off of a semver tag stay in the CI repo until someone promotes them with `promote-images.yml`. Promotion copies the digests that the tag's `build-and-test.yml` run recorded as artifacts, so a tag can be promoted only once that run succeeds, and only while the repo retains its artifacts. Promotion also applies the floating tags (see `.github/scripts/container-images/floating_image_tags.py`), computed against the tags already in `pelican_platform`:

- `latest` tracks the highest release before v26.
- From v26 on, `vN.0` tracks the highest `vN.0.z`, and `vN.x` tracks the highest `vN.y.z` with `y >= 1` (`x` being a literal, here).

## GitHub releases

On a semver tag, in the repos listed in `config.sh`, `release.yml` runs GoReleaser (configured by `.goreleaser.in.yml`), which creates a draft GitHub release, flagged as a pre-release, with the binaries, archives, packages, and checksums. Drafts are visible only to users with write access to the repo, and remain editable until published.

`post-release.yml` runs on the `released` event: when a release is published as a full release, or when a published pre-release is changed to one. It does not run for drafts or pre-releases.

## Cutting a release

1. Push a semver tag. `build-and-test.yml`, `release.yml`, and the macOS and Windows tests run.
1. Once they pass, review the draft release. Publish it, either as a pre-release (for an RC to be shared) or as a full release.
1. Run "Promote Container Images" with the tag. Unless the tag is an RC, its release must be published as a full release. A reviewer for the `image-promotion` environment must approve the run; its summary lists the images and digests to be copied. Promote one tag at a time, and check that each run finishes: dispatching a third run while one is still in progress cancels the second. If a run fails, re-run it.

For a tag cut only for testing, only step 1 is necessary.

## Required repository configuration

Credentials for registries are environment secrets, so that only the jobs that use them can read them. Each environment's deployment branch or tag policy is what restricts its credentials to the intended refs, so those policies are part of the security model, not just hygiene.

| Environment       | Used by                                            | Deployment refs            | Contents                                                                           |
| ----------------- | -------------------------------------------------- | -------------------------- | ---------------------------------------------------------------------------------- |
| `harbor-ci`       | `build-and-test.yml`, push to `main` or semver tag | branch `main`, semver tags | `PELICAN_HARBOR_PUSH_*`: pull and push on `pelican-ci`                             |
| `harbor-pull`     | `test-linux.yml`, push to `main` or semver tag     | branch `main`, semver tags | `PELICAN_HARBOR_PULL_*`: pull on `pelican-ci`                                      |
| `image-promotion` | `promote-images.yml`, `approve` job                | branch `main`              | Required reviewers; no secrets                                                     |
| `harbor-promote`  | `promote-images.yml`, `promote` job                | branch `main`              | `PELICAN_HARBOR_PUSH_*`: pull on `pelican-ci`, pull and push on `pelican_platform` |

`PELICAN_HARBOR_PUSH_*` means the pair `PELICAN_HARBOR_PUSH_USER` and `PELICAN_HARBOR_PUSH_PASSWORD`, and likewise for `PELICAN_HARBOR_PULL_*`. Only the `harbor-promote` credentials may push to `pelican_platform`. They must be a single account, because Docker keeps only one credential per registry host.

The PR, scheduled, and coverage workflows, as well as the devcontainers, pull from `pelican-ci` anonymously, so it must allow that. `harbor-pull` is for forks whose CI repo does not.

None of these credentials may also be available as repository or organization secrets, or any job could read them.

In Harbor, both `pelican-ci` and `pelican_platform` must have a tag immutability rule for `v*.*.*` that does not match the floating tags. Any workflow run for `main` or a semver tag can push to `pelican-ci`, so without the rule, a tag's images there could be replaced after its build pushed them.

The rule limits how a failed tag build can be re-run:

- Before the build creates any multi-architecture manifests, re-run it however you like; the per-architecture images are pushed by digest only.
- After that, re-run only its failed jobs, while the per-architecture digests are still available. A job that already pushed its manifest checks that the tag still refers to it, and skips the push. Re-running all jobs rebuilds the images with new digests, so the check fails.
- If the check fails on the first attempt, something else pushed the tag's images first; find out what before cutting a new tag. If a re-run fails, cut a new tag.

## Forks

Forks listed in `.github/scripts/container-images/config.sh` behave as this repo does, but with their own repos. A fork with a CI repo pushes images built off of `main` and off of semver tags, and creates draft releases. A fork that also has a release repo can promote images, so that it can test the whole process. See "Pull Requests that Modify Pelican's Dependencies" in [CONTRIBUTE.md](../../CONTRIBUTE.md#pull-requests-that-modify-pelicans-dependencies) for the setup.
