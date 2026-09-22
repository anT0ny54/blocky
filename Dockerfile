FROM spx01/blocky:latest

COPY config.yml /app/config.yml

ENV BLOCKY_CONFIG_FILE=/app/config.yml

EXPOSE 4000
