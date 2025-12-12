# Pelican - AI Agent Instructions

This document provides guidance for AI coding agents (including GitHub Copilot) when working with the Pelican codebase.

## Problem-Solving Approach

When presented with an issue or bug, always ask: "Is this an isolated bug, or does it represent a _class_ of bugs that can be fixed?"

For example, if an issue reports "there's a typo in the config name we pass as a string to a function," the immediate fix is correcting the typo. However, the better observation is: "this function takes config params as strings rather than as typed params, which introduces the ability to make typos. I can solve this and all future typo bugs by changing the signature to make typos impossible."

Always seek to prevent entire classes of problems by asking: "How can I prevent other bugs like this in the future?"

## Project Overview

Pelican is a data federation platform that allows users to serve and access datasets through a distributed network of origins and caches. The project includes both server components (Registry, Director, Origin, Cache) and client tools for data transfer.

## Tech Stack

### Backend (Go)
- **Language**: Go 1.24+
- **Web Framework**: Gin (HTTP server)
- **CLI Framework**: Cobra
- **Configuration**: Viper
- **Logging**: Logrus
- **Database**: SQLite with GORM (ORM) and Goose (migrations)
- **API Documentation**: OpenAPI V2.0
- **Storage Backend**: XRootD

### Frontend (TypeScript/React)
- **Language**: TypeScript
- **Framework**: React 19.x with Next.js 15.x
- **UI Library**: Material-UI (MUI) v7
- **Charts**: Chart.js with various plugins
- **Build Tool**: Next.js with Turbo
- **Testing**: Jest
- **Linting**: ESLint
- **Formatting**: Prettier

### Additional Dependencies
- **XRootD**: Underlying storage management for Origins and Caches
- **Prometheus**: Server observability and monitoring
- **OA4MP**: OAuth Server

## Code Organization

- `broker/` - Broker service implementation
- `cache/` - Cache server implementation
- `client/` - Client-side code for data transfers
- `cmd/` - CLI commands using Cobra
- `config/` - Configuration management
- `daemon/` - Daemon utilities
- `database/` - Database models and migrations
- `director/` - Director service for federation coordination
- `docs/` - Documentation and parameter definitions (use one sentence per line for markdown files)
- `origin/` - Origin server implementation
- `registry/` - Registry service for namespace management
- `server_utils/` - Shared utilities for server components
- `token/` - Token generation and validation
- `web_ui/frontend/` - Next.js web interface
- `xrootd/` - XRootD integration

## Building and Testing

### Build Commands

**Full build with GoReleaser:**
```bash
goreleaser build --clean --snapshot
```

**Faster build for testing (single architecture):**
```bash
goreleaser build --clean --snapshot --single-target
```

**Development build (faster):**
```bash
make pelican-dev-build
```
_Note: Requires creating a `.goreleaser.dev.yml` configuration file. See README.md for an example configuration._

**Build web UI:**
```bash
make web-build
```

### Test Commands

**Go tests:**
```bash
go test ./...
```

**Test individual modules:**
```bash
cd director && go test
```

**Frontend tests:**
```bash
cd web_ui/frontend
npm test
```

### Linting

**Go linting:**
```bash
golangci-lint run
```

**Go formatting:**
```bash
gofmt -w .
```

**Frontend linting:**
```bash
cd web_ui/frontend
npm run lint
```

**Frontend formatting:**
```bash
cd web_ui/frontend
npm run format        # Check formatting
npm run format:fix    # Fix formatting
```

## Code Conventions

### Go Code

1. **License Headers**: All Go files must include the Apache 2.0 license header at the top (use current year):
   ```go
   /***************************************************************
    *
    * Copyright (C) {YEAR}, Pelican Project, Morgridge Institute for Research
    *
    * Licensed under the Apache License, Version 2.0 (the "License"); you
    * may not use this file except in compliance with the License.  You may
    * obtain a copy of the License at
    *
    *    http://www.apache.org/licenses/LICENSE-2.0
    *
    * Unless required by applicable law or agreed to in writing, software
    * distributed under the License is distributed on an "AS IS" BASIS,
    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    * See the License for the specific language governing permissions and
    * limitations under the License.
    *
    ***************************************************************/
   ```

2. **Package Naming**: Use lowercase package names matching the directory name

3. **Error Handling**: Always check and handle errors appropriately

4. **Testing**: Place test files alongside source files with `_test.go` suffix. Tests should be isolated (use temp directories and config reset functions) and not depend on state from other tests.

5. **Imports**: Organize imports in three groups separated by blank lines:
   ```go
   import (
       // Standard library imports (alphabetized)
       "encoding/json"
       "net/http"
       "time"

       // External dependencies (alphabetized)
       "github.com/google/uuid"
       "github.com/pkg/errors"

       // Pelican internal packages (alphabetized)
       "github.com/pelicanplatform/pelican/param"
       "github.com/pelicanplatform/pelican/utils"
   )
   ```

### TypeScript/React Code

1. **Components**: Use functional components with hooks

2. **Type Safety**: Prefer explicit types over `any`

3. **File Organization**: 
   - Components in `web_ui/frontend/components/`
   - Pages/routes in `web_ui/frontend/app/`
   - Utilities in `web_ui/frontend/helpers/`
   - Custom hooks in `web_ui/frontend/hooks/`

4. **Styling**: Use Material-UI components and styling system

5. **Formatting**: Follow Prettier configuration (`.prettierrc.json`)

## Development Workflow

### Environment Setup

Pelican uses Docker containers and VSCode Dev Containers for development. See [CONTRIBUTE.md](CONTRIBUTE.md) for detailed setup instructions.

Key steps:
1. Fork and clone the repository
2. Install Docker and VSCode
3. Pull the development container: `hub.opensciencegrid.org/pelican_platform/pelican-dev:latest-itb`
4. Create `.devcontainer/devcontainer.json` using the template from `dev/devcontainer.json`
5. Build Pelican from source inside the container

### Pull Request Guidelines

- Address a single concern with minimal changes
- Add tests for new functionality or bug fixes
- Update documentation in `docs/` folder if needed (use one sentence per line for markdown)
- Follow the ["fork-and-pull" Git workflow](https://github.com/susam/gitpr)
- At least one core contributor must review and approve changes
- Run linters and tests before submitting
- Rebase against main and wait for passing tests before merge (tests run in dev container built from main branch)

### Configuration

- Server configuration: Prefer YAML files (typically `pelican.yaml`) over command-line arguments (except when testing command-line arguments)
- Client configuration: Can use federation discovery URLs or explicit configuration
- Parameters documented in `docs/parameters.yaml`

## Key Features and Patterns

### Object Transfer

- Client commands: `pelican object get`, `pelican object put`, `pelican object copy`
- All transfers use HTTP (pelican:// and osdf:// URLs specify federation discovery, not transfer protocol)
- Checksum verification (MD5, SHA1, CRC32)
- Resume capabilities for interrupted transfers

### Federation Model

- **Director**: Routes client requests to appropriate origins/caches
- **Registry**: Manages namespace registrations
- **Origins**: Serve data from storage backends
- **Caches**: Provide distributed caching layer

### Authorization

- Token-based authorization (not authentication) with support for various issuers
- OAuth integration via CILogon for web authentication
- Support for WLCG tokens (https://github.com/WLCG-AuthZ-WG/common-jwt-profile/blob/master/profile.md)
- Support for SciTokens (https://scitokens.org/technical_docs/Claims)

### Monitoring

- Prometheus metrics integration
- Health checks for all services
- Performance monitoring through web UI

## API Documentation

API endpoints are documented using OpenAPI V2.0. The specification is generated from code annotations.

## Testing Philosophy

- Unit tests for individual functions and components
- Integration tests for service interactions
- End-to-end tests in `e2e_fed_tests/`
- Test utilities in `test_utils/` and `fed_test_utils/`

## Security Considerations

- TLS/HTTPS by default for all services
- Token validation for authenticated operations
- Regular dependency updates
- CodeQL analysis in CI/CD pipeline

## Documentation

- User documentation: [docs.pelicanplatform.org](https://docs.pelicanplatform.org/)
- API documentation: Available through web UI at `/api/docs`
- Parameter reference: `docs/parameters.yaml`
- HTTP headers: `docs/pelican-http-headers.md`
- Error codes: `docs/error_codes.yaml`

## Common Gotchas

1. **XRootD Integration**: Origins and Caches require XRootD to be properly configured
2. **MaxMind License**: Director benefits from a MaxMind license key for GeoIP lookups (functions without it, but cannot use GeoIP services)
3. **OAuth Setup**: Registry requires CILogon OAuth credentials for web authentication
4. **Port Conflicts**: Default ports may conflict with local services
5. **TLS Certificates**: Development often uses `TLSSkipVerify: true` but production requires proper certificates

## Useful Commands

```bash
# Run a local federation ("federation in a box")
pelican serve --module director,registry,origin,cache

# Serve an origin
pelican origin serve -f https://director.example.com -v /tmp/stash/:/test

# Download an object
pelican object get /test/file ./local-file

# Generate configuration
go generate ./...

# Validate parameters
make validate-parameters
```

## Resources

- Main Repository: https://github.com/PelicanPlatform/pelican
- Documentation: https://docs.pelicanplatform.org/
- Website: https://pelicanplatform.org/
- Contributing Guide: [CONTRIBUTE.md](CONTRIBUTE.md)
- Security Policy: [SECURITY.md](SECURITY.md)
