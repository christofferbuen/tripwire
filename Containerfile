# Tripwire receiver.
#
# CPython 3.14.7 on Alpine 3.24, chosen 2026-09-08. 3.14.7 is a security
# release: it closes tarfile extraction-filter path-traversal bypasses,
# scopes HTTPPasswordMgr credentials to the URL scheme (CVE-2026-15806),
# and bundles libexpat 2.8.1 (CVE-2026-45186) and pip 26.1 (CVE-2026-3219).
# Python 3.15 was still at release candidate on that date.
#
# The application imports nothing outside the standard library, so there are
# no wheels to build and no dependency tree to audit. The only things that
# need patching here are CPython and the Alpine base.
#
# For a reproducible build, resolve the tag to a digest once and pin that
# instead:
#   podman image inspect docker.io/library/python:3.14.7-alpine3.24 \
#     --format '{{index .RepoDigests 0}}'
# Re-resolve deliberately when you want the newer patch level, so an upstream
# rebuild never changes what you ship without you noticing.

FROM docker.io/library/python:3.14.7-alpine3.24

# No .pyc files, because the root filesystem is read-only at runtime.
# Unbuffered output so `podman logs -f` shows hits as they land.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# A dedicated unprivileged account. High fixed UID so it cannot collide with
# a real user if the volume is ever inspected from the host.
RUN addgroup -S -g 10001 tripwire \
 && adduser -S -u 10001 -G tripwire -H -s /sbin/nologin tripwire \
 && mkdir -p /data \
 && chown 10001:10001 /data

WORKDIR /app
COPY receiver.py analyze.py /app/
COPY site/ /app/site/
RUN chmod 0444 /app/receiver.py /app/analyze.py \
 && find /app/site -type f -exec chmod 0444 {} + \
 && find /app/site -type d -exec chmod 0555 {} +

USER 10001:10001

VOLUME ["/data"]
EXPOSE 8787

# Only survives into the image when built with `podman build --format docker`.
# Podman's default OCI format discards HEALTHCHECK with a warning. run.sh
# passes that flag; compose.yaml and the quadlet unit instead declare their
# own check at run time, so all three paths end up with a working probe.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request as u, sys; \
sys.exit(0 if u.urlopen('http://127.0.0.1:8787/healthz', timeout=3).status == 200 else 1)"

ENTRYPOINT ["python3", "/app/receiver.py"]

# 0.0.0.0 here is the container's own network namespace, not the host. Real
# exposure is decided by how the port is published: run.sh, compose.yaml and
# the quadlet unit all bind it to 127.0.0.1 on the host, and a TLS proxy you
# control is what should face the network.
#
# The one way to get this wrong is --network=host, which collapses the
# namespace and turns this into a genuine 0.0.0.0 listener. Do not do that.
CMD ["--host", "0.0.0.0", "--port", "8787", "--db", "/data/tripwire.sqlite3"]
