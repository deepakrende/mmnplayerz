FROM node:20-alpine
WORKDIR /app
RUN apk add --no-cache ffmpeg su-exec
COPY server-prod.js iptv-player.html landing.html admin.html entrypoint.sh ./
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh
EXPOSE 8787
HEALTHCHECK CMD wget -qO- http://localhost:${PORT:-8787}/healthz || exit 1
CMD ["./entrypoint.sh"]
