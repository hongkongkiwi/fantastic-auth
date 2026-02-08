#!/bin/bash
set -e

echo "🚀 Vault Auth Server Setup"
echo "=========================="

# Check if .env exists
if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "⚠️  Please edit .env with your configuration"
fi

# Load environment variables
export $(grep -v '^#' .env | xargs)

# Check dependencies
echo "Checking dependencies..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose found"

# Create necessary directories
mkdir -p ops
mkdir -p logs

# Start infrastructure services
echo ""
echo "📦 Starting infrastructure services..."
docker-compose up -d postgres redis

# Wait for PostgreSQL to be ready
echo ""
echo "⏳ Waiting for PostgreSQL to be ready..."
until docker-compose exec -T postgres pg_isready -U vault; do
    sleep 1
done
echo "✅ PostgreSQL is ready"

# Run migrations
echo ""
echo "🗄️  Running database migrations..."
docker-compose exec -T postgres psql -U vault -d vault -f /docker-entrypoint-initdb.d/0001_initial_schema.sql || true
docker-compose exec -T postgres psql -U vault -d vault -f /docker-entrypoint-initdb.d/0002_security_roles.sql || true

echo "✅ Migrations complete"

# Start the application
echo ""
echo "🚀 Starting Vault Auth Server..."
docker-compose up -d vault

echo ""
echo "✅ Setup complete!"
echo ""
echo "Services:"
echo "  - Vault API:     http://localhost:3000"
echo "  - Metrics:       http://localhost:9090/metrics"
echo "  - PostgreSQL:    localhost:5432"
echo "  - Redis:         localhost:6379"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f vault"
echo ""
echo "To stop:"
echo "  docker-compose down"
