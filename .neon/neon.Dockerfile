FROM traefik:2.11

EXPOSE 80

COPY traefik.tar.gz /traefik.tar.gz

RUN tar -xzf traefik.tar.gz \
  && mv traefik /usr/local/bin \
  && rm traefik.tar.gz

CMD ["traefik"]
