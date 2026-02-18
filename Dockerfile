FROM oven/bun:1.3-slim

ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=$GIT_COMMIT

WORKDIR /app

# Install dependencies (layer caching)
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Copy source
COPY src/ src/
COPY .env.example .env.example
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

EXPOSE 3000

ENTRYPOINT ["./entrypoint.sh"]
