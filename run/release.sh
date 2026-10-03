#!/usr/bin/env bash
# Cuts a release: bumps source/vcpkg.json's version, tags it, pushes, and
# (if `gh` is installed) creates a GitHub Release with auto-generated notes.
# This script never deploys anything.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_branch="develop"

usage() {
  echo "usage: $(basename "$0") <version>   (e.g. 0.2.0, no leading 'v')" >&2
  exit 1
}

[[ $# -eq 1 ]] || usage
version="$1"
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
tag="v${version}"

cd "${repo_root}"

current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "${current_branch}" != "${release_branch}" ]]; then
  echo "error: on branch '${current_branch}', releases are cut from '${release_branch}'" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean" >&2
  git status --short >&2
  exit 1
fi

git fetch origin "${release_branch}" --quiet
if [[ "$(git rev-parse HEAD)" != "$(git rev-parse "origin/${release_branch}")" ]]; then
  echo "error: local ${release_branch} is not up to date with origin/${release_branch}" >&2
  exit 1
fi

if git rev-parse "${tag}" >/dev/null 2>&1; then
  echo "error: tag ${tag} already exists" >&2
  exit 1
fi

echo "==> bumping source/vcpkg.json to ${version}"
sed -i.bak "s/\"version\": \"[0-9]*\.[0-9]*\.[0-9]*\"/\"version\": \"${version}\"/" source/vcpkg.json
rm -f source/vcpkg.json.bak
git diff --stat -- source/vcpkg.json

read -r -p "Commit, tag ${tag}, and push to origin/${release_branch}? [y/N] " confirm
if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
  echo "aborted (vcpkg.json edit left unstaged, revert with: git checkout -- source/vcpkg.json)"
  exit 1
fi

git add source/vcpkg.json
git commit -m "Release ${tag}"
git tag -a "${tag}" -m "Release ${tag}"
git push origin "${release_branch}"
git push origin "${tag}"

if command -v gh >/dev/null 2>&1; then
  gh release create "${tag}" --title "${tag}" --generate-notes
else
  echo "==> gh CLI not found; create the release manually:"
  echo "    gh release create ${tag} --title ${tag} --generate-notes"
fi

echo "==> release ${tag} pushed."
