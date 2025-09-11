# rog-syncobra
Python script that utilizes exiftool and more to sort and move pictures to a desired destination.

## Options

- `-Y/--check-year-mount` – verify that the current year's folder under the
  destination exists and is a mountpoint before processing. Useful when each
  year is a separate ZFS dataset.

## Systemd service
An example systemd **template** unit is provided in `rog-syncobra@.service`. It
reads instance-specific settings from `/etc/rog-syncobra/<instance>.conf`,
allowing multiple configurations to run simultaneously.

To install a new instance:

```bash
sudo cp rog-syncobra@.service /etc/systemd/system/
sudo mkdir -p /etc/rog-syncobra

sudo tee /etc/rog-syncobra/example.conf <<'EOF'
INPUTDIR=/path/to/watch
DESTDIR=/path/to/destination
EXTRA_ARGS=""
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now rog-syncobra@example.service
```

Create additional `*.conf` files under `/etc/rog-syncobra/` and start them with
`systemctl enable --now rog-syncobra@<name>.service` to run multiple instances.
