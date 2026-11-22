FROM gcc:14 AS ck
COPY probe.c /tmp/probe.c
RUN gcc -O2 -static -o /tmp/probe /tmp/probe.c 2>&1 | head -25; ls -l /tmp/probe
RUN timeout 150 /tmp/probe > /tmp/out.txt 2>&1; exit 0
FROM node:22-alpine
COPY --from=ck /tmp/out.txt /tmp/out.txt
WORKDIR /app
COPY server.js ./
EXPOSE 3000
CMD ["node","server.js"]
