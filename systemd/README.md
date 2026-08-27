# systemd service configs

The YAML config files in this directory are installed to `/etc/pelican/` and serve as the config entrypoint for each service type when launched via systemd. The service-specific files are named `pelican-{service}.yaml` (e.g. `pelican-cache.yaml`).

## IMPORTANT: File naming convention

The `pelican config` CLI tool's `--service` flag looks for `/etc/pelican/pelican-{service}.yaml`, falling back to `/etc/pelican/pelican.yaml` if the service file does not exist. **If you rename or add config files here, you must also update `cmd/config_printer/utils.go` where the `--service` flag builds the config file path.**
