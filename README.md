# Diun image updater

Diun scans the curated image inventory on startup and every six hours. Its
authenticated webhook sends registry changes to the host-side, allow-listed
Compose updater. The updater pulls and redeploys only configured services,
checks that updated containers are running and healthy, and sends one Telegram
message through HomeAlert only after an image actually changed or an update
attempt failed. Registry tag detections are not sent directly to Telegram.

The Telegram token and chat IDs stay in root-owned files on the host. Diun does
not receive those credentials. The updater reads them only when it needs to
report an update result. The webhook remains authenticated, and the updater does
not expose the Docker socket to Diun. Diun uses Docker's default bridge network
because the daemon has no free address pools for another Compose network; no
host ports are published.

`images.yml` lists the upstream images tracked by the monitor. Locally built
images (`*:local`, project-built images, and anonymous image IDs) are excluded
because they do not identify an upstream registry image. Exact deployed tags
are tracked for digest changes. For selected images, `watch_repo` and stable
version filters also detect newer version tags. Maintain this inventory and
the allow-list in `updater.py` when deployed stacks or tags change.

The updater service is installed as `diun-updater.service`; inspect its logs
with `journalctl -u diun-updater`. Diun's scan and webhook logs are available
with `docker logs image-update-monitor`.

## Public snapshot configuration

This snapshot preserves the updater and curated inventory. Host-specific home
paths use `/home/example/`, and the secondary disk target uses the example
name `yandexdisk_secondary`. Adapt those values in `updater.py` and the service
unit to the intended host before installation.

The real `.env`, Telegram token, recipient IDs, and Docker registry credentials
are deliberately absent. `.env.example` documents the required webhook setting;
provide a private random value in a local `.env` file. Provision the root-owned
credential files referenced by the code and Compose separately. No service is
installed or started by this snapshot.
