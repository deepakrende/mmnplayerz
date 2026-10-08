FROM node:20-alpine
WORKDIR /app
COPY . .
USER node
EXPOSE 8787
HEALTHCHECK CMD wget -qO- http://localhost:${PORT:-8787}/healthz || exit 1
CMD ["node", "server-prod.js"]
