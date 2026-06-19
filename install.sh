#!/bin/bash
set -e

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Docker is required but not installed."
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "Docker Compose is required."
    exit 1
fi

# Copy .env if missing
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example"
fi

# Start services
docker compose up -d
echo "Services started."
