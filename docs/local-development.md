# Building

You will need an installation of Docker and `make` to build Hera and its dependencies.

The [Makefile](https://github.com/stayallive/hera/blob/master/Makefile) defines several commands that you can run for building and testing.

## Build Process

Run `make build` to build a new image with a new Hera binary. `make build` uses the [Dockerfile](https://github.com/stayallive/hera/blob/master/Dockerfile) to first make the binary and then the final image as a multi-stage build.

## Running

After a successful build, use the `make run` command to start a container based on the new image.

Note: the `make run` command expects a Docker network as well as a `.certs` folder at the root of the project directory containing your `.pem` files.

Create a new network if it doesn't exist already:

```
$ docker network create hera
```

Run the container:

```
$ make run

docker run --rm --name=hera --network=hera -v /var/run/docker.sock:/var/run/docker.sock -v ~/development/hera/certs:/certs hera
[s6-init] making user provided files available at /var/run/s6/etc...exited 0.
[s6-init] ensuring user provided files have correct perms...exited 0.
[fix-attrs.d] applying ownership & permissions fixes...
[fix-attrs.d] 01-log-permissions: applying...
[fix-attrs.d] 01-log-permissions: exited 0.
[fix-attrs.d] done.
[cont-init.d] executing container initialization scripts...
[cont-init.d] 01-setup-logs: executing...
[cont-init.d] 01-setup-logs: exited 0.
[cont-init.d] 02-symlink-certs: executing...
[cont-init.d] 02-symlink-certs: exited 0.
[cont-init.d] done.
[services.d] starting services
[services.d] done.
[INFO] Hera v0.2.4 has started
[INFO] Found certificate: mysite.com.pem
[INFO] Hera is listening
```

## Creating Tunnels

You can easily create new tunnels with `make tunnel`. This will start a new `nginx` container with the required Hera configuration. Specify the tunnel's hostname using a `HOSTNAME` environment variable. Example:

```
$ HOSTNAME=mysite.com make tunnel

docker run --rm --label hera.hostname=mysite.com --label hera.port=80 --network=hera nginx
```

## Testing Garbage Collection

To test garbage collection behavior:

```bash
# Run Hera in dry-run mode to preview what would be deleted
docker run --rm --name=hera --network=hera \
  -e HERA_GC_DRY_RUN=true \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ~/development/hera/certs:/certs \
  hera

# Run with custom minimum age (5 minutes for faster testing)
docker run --rm --name=hera --network=hera \
  -e HERA_GC_MIN_AGE_MINUTES=5 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ~/development/hera/certs:/certs \
  hera
```

## Testing

Run `make test` to run the unit tests. `make test` uses the first stage of the Dockerfile to create a "builder" image and then runs the tests in a temporary container.

```
$ make test

docker build --target builder -t hera-builder .
Sending build context to Docker daemon  796.2kB
Step 1/5 : FROM golang:latest AS builder
 ---> d0e7a411e3da
...
Successfully built 973961923ea3
Successfully tagged hera-builder:latest
docker run --rm -v /Users/andrew/development/hera/hera:/hera -w /hera hera-builder go test -v
...
PASS
ok  	_/hera	0.013s
```