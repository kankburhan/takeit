#!/bin/bash

# release.sh - Script to release a new version of takeit

set -e

if [ -z "$1" ]; then
    echo "Usage: ./release.sh <version>"
    echo "Example: ./release.sh v1.0.0"
    exit 1
fi

VERSION=$1

# Ensure the version starts with 'v'
if [[ $VERSION != v* ]]; then
    VERSION="v$VERSION"
fi

echo "🚀 Preparing release $VERSION..."

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Error: Working directory is not clean. Please commit or stash changes."
    exit 1
fi

# Create tag
echo "🏷️  Creating git tag $VERSION..."
git tag -a "$VERSION" -m "Release $VERSION"

# Push tag
echo "⬆️  Pushing tag to origin..."
git push origin "$VERSION"

# Run GoReleaser if available
if command -v goreleaser &> /dev/null; then
    echo "📦 Running GoReleaser..."
    goreleaser release --clean
    echo "✅ Release $VERSION published successfully!"
else
    echo "⚠️  GoReleaser not found. Tag pushed, but binaries not built."
    echo "👉 Install GoReleaser to automate binary release: https://goreleaser.com/"
fi
