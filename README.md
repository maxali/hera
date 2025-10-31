# Hera

> Hera automates the creation of [Cloudflare Tunnels](https://www.cloudflare.com/products/tunnel/) to easily and securely expose your local services to the outside world

Hera lets you instantly access services outside of your local network with a custom domain using tunnels and is a more secure alternative than using port forwarding or dynamic DNS.

Hera monitors the state of your configured services to instantly start a tunnel when the container starts. Tunnel processes are also monitored to ensure persistent connections and to restart them in the event of sudden disconnects or shutdowns. Tunnels are automatically restarted when their containers are restarted, or gracefully shutdown if their containers are stopped.

_This repository started as a fork of [aschzero/hera](https://github.com/aschzero/hera), huge thanks to them for the initial work._

## Features

* Continuously monitors the state of your services for automated tunnel creation.
* Revives tunnels on running containers when Hera is restarted.
* Automatically cleans up orphaned tunnels from Cloudflare when containers are removed.
* Uses native Go process management to ensure active tunnel processes are kept alive.
* Low memory footprint and high performance – services can be accessed through a tunnel within seconds.
* Requires a minimal amount of configuration so you can get up and running quickly.
* Supports multiple Cloudflare domains.

## Image Registries

Images are available on the following registries:

- [GitHub Container Registry](https://github.com/stayallive/hera/pkgs/container/php) (pull using `ghcr.io/stayallive/hera:latest`)
- [Docker Hub](https://hub.docker.com/r/stayallive/hera) (pull using `stayallive/hera:latest`)

They are listed as `stayallive/hera` and provides an image for `linux/amd64`.

[![Built with Depot](https://depot.dev/badges/built-with-depot.svg)](https://depot.dev/?utm_source=stayallive)

## How Hera Works

Hera attaches to the Docker daemon to watch for changes in state of your configured containers. When a new container is started, Hera checks that it has the proper configuration as well as making sure the container can receive connections. If it passes the configuration checks, Hera spawns a new process to create a persistent tunnel connection.

In the event that a container with an active tunnel has been stopped, Hera gracefully shuts down the tunnel process.

ℹ️ Hera only monitors the state of containers that have been explicitly configured for Hera. Otherwise, containers and their events are completely ignored.

## Getting Started

### Prerequisites

* Installation of Docker with a client API version of 1.22 or later
* An active domain in Cloudflare with the Argo Tunnel service enabled
* A valid Cloudflare certificate (see [Obtain a Certificate](#obtain-a-certificate))

### Obtain a Certificate

Hera needs a Cloudflare certificate so it can manage tunnels on your behalf.

1. Download a new certificate by visiting: https://dash.cloudflare.com/argotunnel
2. Rename the certificate to match your domain, ending in `.pem`. For example, a certificate for `mysite.com` should be named `mysite.com.pem`.
3. Move the certificate to a directory that can be mounted as a volume (see [Required Volumes](#required-volumes)).

Hera will look for certificates with names matching your tunnels' hostnames and allows the use of multiple certificates. For more info, see [Using Multiple Domains](#using-multiple-domains).

### Create a Network

Hera must be able to connect to your containers and resolve their hostnames before it can create a tunnel. This allows Hera to supply a valid address to Cloudflare during the tunnel creation process.

It is recommended to create a dedicated network for Hera and attach your desired containers to the new network.

For example, to create a network named `hera`:

`docker network create hera`

---

## Running Hera

Hera can be started with the following command:

```
docker run \
  --name=hera \
  --network=hera \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /path/to/certs:/certs \
  stayallive/hera:latest
```

### Required Volumes

* `/var/run/docker.sock` – Attaching the Docker daemon as a volume allows Hera to monitor container events.
* `/path/to/certs` – The directory of your Cloudflare certificates.

### Persisting Logs

You can optionally mount a volume to `/var/log/hera` to persist the logs on your host machine:

```
docker run \
  --name=hera \
  --network=hera \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /path/to/certs:/certs \
  -v /path/to/logs:/var/log/hera \
  stayallive/hera:latest
```

ℹ️ Tunnel log files are named according to their hostname and can be found at `/var/log/hera/<hostname>.log`

### Tunnel Configuration

Hera utilizes labels for configuration as a way to let you be explicit about which containers you want enabled. There are only two labels that need to be defined:

* `hera.hostname` - The hostname is the address you'll use to request the service outside of your home network. It must be the same as the domain you used to configure your certificate and can either be a root domain or subdomain (e.g.: `mysite.com` or `blog.mysite.com`).

* `hera.port` - The port your service is running on inside the container.

⚠️ _Note: you can still expose a different port to your host network if desired, but the `hera.port` label value needs to be the internal port within the container._

Here's an example of a container configured for Hera with the `docker run` command:

```
docker run \
  --network=hera \
  --label hera.hostname=mysite.com \
  --label hera.port=80 \
  nginx
```

That's it! After the tunnel propagates, you would be able to see the default nginx welcome page when requesting `mysite.com`.

Viewing the logs would output something similar to below:

```
$ docker logs -f hera

[INFO] Hera container found, connecting to 5aa5a300dd0e...
[INFO] Registering tunnel mysite.com
time="2018-08-11T08:38:40Z" level=info msg="Applied configuration from /var/run/s6/services/mysite.com/config.yml"
time="2018-08-11T08:38:40Z" level=info msg="Proxying tunnel requests to http://172.18.0.3:80"
time="2018-08-11T08:38:40Z" level=info msg="Starting metrics server" addr="127.0.0.1:40521"
time="2018-08-11T08:38:41Z" level=info msg="Connected to SEA"
time="2018-08-11T08:38:41Z" level=info msg="Route propagating, it may take up to 1 minute for your new route to become functional"
...
```

#### Stopping Tunnels

Stopping a container with an active tunnel will trigger it to shut down:

```
$ docker stop nginx
$ docker logs -f hera

[INFO] Stopping tunnel mysite.com
time="2018-08-11T09:00:53Z" level=info msg="Initiating graceful shutdown..."
time="2018-08-11T09:00:53Z" level=info msg="Quitting..."
time="2018-08-11T09:00:53Z" level=info msg="Metrics server stopped"
```

### Using Multiple Domains

You can use multiple domains as long as there are certificates for each domain with names matching the base hostname of the tunnel. Names are matched according to the pattern `*.domain.tld` and must be placed in the same directory.

For example, tunnels for `mysite.com` or `blog.mysite.com` will use the certificate named `mysite.com.pem`.

If a certificate with a matching domain cannot be found, it will look for `cert.pem` in the same directory as a fallback.

### Garbage Collection

Hera automatically cleans up orphaned tunnels from Cloudflare on startup. Orphaned tunnels occur when containers are removed while Hera is stopped, or if Hera crashes during container shutdown.

**Safety Features:**
- Only deletes tunnels with zero active connections
- Only deletes tunnels older than 10 minutes (configurable)
- Re-verifies tunnels are still orphaned immediately before deletion
- Never deletes tunnels for running containers

**Configuration:**

```bash
# Disable garbage collection (enabled by default)
docker run -e HERA_GC_ENABLED=false ...

# Preview what would be deleted without actually deleting
docker run -e HERA_GC_DRY_RUN=true ...

# Change minimum tunnel age before deletion (default: 10 minutes)
docker run -e HERA_GC_MIN_AGE_MINUTES=15 ...
```

**What Gets Deleted:**
Tunnels are considered orphaned when:
- No container exists with matching `hera.hostname` label
- Tunnel has zero active connections
- Tunnel is older than the minimum age threshold
- Tunnel is not in Hera's active registry

⚠️ **Note:** Manually created tunnels (not managed by Hera) are safe from garbage collection if they meet the age and connection requirements. Use `HERA_GC_DRY_RUN=true` to preview deletions before enabling.

---

## Examples

### Subdomains

An example of a tunnel for Kibana pointing to `kibana.mysite.com`:

```
docker run \
  --name=kibana \
  --network=hera \
  --label hera.hostname=kibana.mysite.com \
  --label hera.port=5601 \
  -p 5000:5601 \
  docker.elastic.co/kibana/kibana:6.2.4
```

### Docker Compose

```yaml
version: '3'

services:
  hera:
    image: stayallive/hera:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /path/to/certs:/certs
    networks:
      - hera
    environment:
      # Optional: Configure garbage collection
      - HERA_GC_ENABLED=true          # Enable/disable GC (default: true)
      - HERA_GC_MIN_AGE_MINUTES=10    # Minimum tunnel age (default: 10)
      # - HERA_GC_DRY_RUN=true        # Preview deletions without executing

  nginx:
    image: nginx:latest
    networks:
      - hera
    labels:
      hera.hostname: mysite.com
      hera.port: 80

networks:
  hera:
```

## Contributing

* If you'd like to contribute to the project, refer to the [contributing documentation](https://github.com/stayallive/hera/blob/master/.github/CONTRIBUTING.md).
* Read the [Development](https://github.com/stayallive/hera/wiki/Development) wiki for information on how to setup Hera for local development.

## Security Vulnerabilities

If you discover a security vulnerability within this package, please send an e-mail to Alex Bouma at `alex+security@bouma.me`. All security vulnerabilities will be swiftly
addressed.

## License

This package is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
