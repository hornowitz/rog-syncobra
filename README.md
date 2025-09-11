# rog-syncobra
Python script that utilizes exiftool and more to sort and move pictures to a desired destination.

## Options

- `-Y/--check-year-mount` – verify that the current year's folder under the
  destination exists and is a mountpoint before processing. Useful when each
  year is a separate ZFS dataset.
