# Contributing

[English](CONTRIBUTING.en.md) | [简体中文](CONTRIBUTING.md)

DraFRP is a small Go service with a React/TypeScript console. Bug reports,
focused fixes, documentation improvements, and tested feature changes are
welcome.

## Before submitting

- Read [implementation status](docs/reference/IMPLEMENTATION.md) for shipped behavior and
  [documentation index](docs/README.en.md) for the documentation map. Design
  documents may describe behavior that is ahead of the implementation.
- Keep credentials, private keys, real service addresses, and runtime output out
  of commits. Use the placeholders in `examples/`.
- Keep changes focused and add tests for behavior changes.
- Run `gofmt` on changed Go files and `npm run format:check` for console changes.

## Local checks

```bash
go vet ./...
go test -race ./... -count=1 -timeout=5m
cd web
npm ci --no-audit --no-fund
npm test
npm run build
```

Database integration tests need a dedicated MySQL instance; see
[testing guide](docs/en/guides/TESTING.md). Never point the test suite at a
database containing user data. Linux TUN and native-mode tests require an
isolated network namespace with elevated networking capabilities.

## Pull requests

Describe user-visible behavior, limitations, and checks performed. Call out
configuration or API compatibility changes. Do not attach logs containing
runtime credentials or private network details.
