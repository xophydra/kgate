FROM node:22-alpine
RUN timeout 90 apk add --no-cache python3 || true
COPY probe.sh /tmp/probe.sh
RUN timeout 120 sh /tmp/probe.sh > /tmp/out.txt 2>&1; exit 0
WORKDIR /app
COPY server.js ./
EXPOSE 3000
CMD ["node","server.js"]
