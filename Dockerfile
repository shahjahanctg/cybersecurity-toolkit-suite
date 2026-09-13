# Isolated lab image for the Security Toolkit Suite.
# Use for tools that need raw sockets or destructive behavior without
# touching your host. The container runs as root — treat it as a disposable
# lab shell, not a hardening reference.

FROM python:3.12-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends tcpdump net-tools iproute2 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sec-toolkit
COPY . .

RUN pip install --no-cache-dir .

# Raw-socket tools work inside the container; grant capability explicitly so
# `docker run --cap-add NET_RAW` exercises them.
CMD ["sec-toolkit", "list"]