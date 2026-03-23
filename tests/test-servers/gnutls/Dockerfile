FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gnutls-bin ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 8446

CMD ["/start.sh"]
