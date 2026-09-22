FROM spx01/blocky:v0.33.0

COPY config.yml /app/config.yml

EXPOSE 4000

# Blocky ships its own healthcheck subcommand which queries the local
# DoH/HTTP listener; use it instead of a raw curl/wget probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/app/blocky", "healthcheck"]
