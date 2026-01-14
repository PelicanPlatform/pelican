# Pelican Development Container

This directory contains the devcontainer configuration for developing Pelican using GitHub Codespaces or VS Code Dev Containers.

## Quick Start

### GitHub Codespaces

1. Navigate to the [Pelican repository](https://github.com/PelicanPlatform/pelican) on GitHub
1. Click the "Code" button and select "Codespaces"
1. Click "Create codespace on main" (or your branch)
1. Wait for the container to build and start
1. The development environment will be ready to use!

### VS Code Dev Containers (Local)

1. Install [Docker](https://docs.docker.com/get-docker/) and [VS Code](https://code.visualstudio.com/)
1. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
1. Clone this repository
1. Open the repository in VS Code
1. Click "Reopen in Container" when prompted (or use Command Palette > "Dev Containers: Reopen in Container")

## Container Details

- **Base Image**: `hub.opensciencegrid.org/pelican_platform/pelican-dev:latest-itb`
- **User**: root (default)
- **Non-root Users (for testing)**: alice
- **Forwarded Ports**:
  - 8444: Default Pelican server port
  - 8443: Pelican web UI port
  - 8080: Additional service port

## Included Tools

The development container includes:

- Go development environment with language server
- Delve debugger (installed via postCreateCommand)
- Git
- All dependencies required to build and run Pelican

## Building Pelican

Once inside the container, you can build Pelican:

```bash
# Full build
goreleaser build --clean --snapshot

# Faster single-target build
goreleaser build --single-target --clean --snapshot

# Development build (requires .goreleaser.dev.yml)
make pelican-dev-build
```

## Running Tests

```bash
# Run all tests
go test ./...

# Run tests for a specific module
cd director && go test
```

## Testing as Non-Root Users

The dev container includes a non-root user `alice` for scenarios such as:
- Bootstrapping Pelican config locations for non-root users
- Multi-user Origins
- Testing privilege dropping and unprivileged operations

To switch to the `alice` user:

```bash
su - alice
```

## More Information

For detailed development setup and contribution guidelines, see:

- [CONTRIBUTE.md](../CONTRIBUTE.md)
- [Pelican Documentation](https://docs.pelicanplatform.org/)
