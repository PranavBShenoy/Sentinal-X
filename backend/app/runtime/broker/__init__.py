"""
SENTINEL-X Constrained Runtime Broker.

The broker is a dedicated, policy-enforcing service that holds the Docker
socket and exposes only the narrow set of operations the Celery worker
requires. The worker never mounts the Docker socket; it talks to the broker
over authenticated HTTP.

Security model:
- The broker decides all security parameters (cap-drop, no-new-privileges,
  read-only rootfs, resource limits, network, port binding).
- The caller sends only minimal operational parameters.
- Privileged containers, host mounts, host networking, host PID namespaces,
  root execution, and Docker exec are rejected by policy.
"""
