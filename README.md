# rog-syncobra
Python script that utilizes exiftool and more to sort and move pictures to a desired destination.

## Options

- `-Y/--check-year-mount` – verify that the current year's folder under the
  destination exists and is a mountpoint before processing. Useful when each
  year is a separate ZFS dataset.

## Systemd service
An example systemd unit is provided in `rog-syncobra.service`. It runs the script in watch mode and restarts on failure.

To install:

```bash
sudo cp rog-syncobra.service /etc/systemd/system/
sudo systemctl daemon-reload

sudo tee /etc/default/rog-syncobra <<'EOF2'
INPUTDIR=/path/to/watch
DESTDIR=/path/to/destination
EXTRA_ARGS=""
EOF2

sudo systemctl enable --now rog-syncobra.service
```
