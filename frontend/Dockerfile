# Веб-интерфейс «Устранения»: сборка статики (Node) и раздача через nginx без root.
# nginx проксирует /api/* на API с отрезанием префикса — интерфейс и API на одном
# origin, CORS не нужен. Адрес API — переменная API_UPSTREAM.

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
# VITE_BASE / VITE_API_BASE: «/» и «/api» отдельно, «/vm/» и «/api/vm» в «Платформе».
ARG VITE_BASE=/
ARG VITE_API_BASE=/api
ENV VITE_BASE=$VITE_BASE VITE_API_BASE=$VITE_API_BASE
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
ENV API_UPSTREAM=http://app:8000 TRUSTED_PROXY=127.0.0.1
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
