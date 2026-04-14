# FLAW143 — Docker socket mounted into container

**Severity:** high · **Tag:** security · CWE-250

## What
Mounting `/var/run/docker.sock` into a container gives that container full control of the Docker daemon — equivalent to root on the host. Use a rootless pattern, socket proxy with strict allow-list, or remote API with TLS client certs instead.

## Fix
See the rule description and the detector at `src/rules/docker_socket_mount.cr`.
