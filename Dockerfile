# Pin the Blocky runtime to the reviewed v0.35.0 release.
FROM spx01/blocky:v0.35.0

COPY config.yml /app/config.yml

# SnapDeploy exposes the HTTP listener for DoH.
EXPOSE 4000

# Inherit Blocky's native healthcheck from the pinned base image. It follows
# ports.dns from the config; the config keeps that listener on loopback:5300.
