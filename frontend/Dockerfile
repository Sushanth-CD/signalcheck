# Multi-stage production Dockerfile for SignalCheck Frontend
FROM node:20-alpine AS builder

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* /app/
RUN npm ci

COPY frontend/ /app/
# Remove any local dev environment files that might have been copied
RUN rm -f /app/.env /app/.env.local /app/.env.development /app/.env.production

# Build static assets using relative API base URL by default for reverse proxy integration
ENV VITE_API_BASE_URL=""
RUN npm run build

# --- Production Static Server Stage (Lightweight NGINX Asset Server) ---
FROM nginx:alpine AS runner

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx/frontend-static.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q -O - http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
