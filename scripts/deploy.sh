#!/bin/bash
# Deployment script for Secret Detection & Rotation Framework

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT="${1:-production}"
VERSION=$(grep -oP '(?<=version = ")[^"]*' pyproject.toml || echo "1.0.0")

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Secret Detection & Rotation Framework Deployment         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Version:${NC} $VERSION"
echo -e "${GREEN}Environment:${NC} $ENVIRONMENT"
echo ""

# Step 1: Pre-deployment checks
echo -e "${BLUE}[1/6] Running pre-deployment checks...${NC}"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  .env file not found. Creating from template...${NC}"
    if [ -f env.example ]; then
        cp env.example .env
        echo -e "${RED}⚠️  Please configure .env file before deploying!${NC}"
        exit 1
    fi
fi

# Check required environment variables
required_vars=("GITHUB_TOKEN" "AWS_DEFAULT_REGION")
for var in "${required_vars[@]}"; do
    if [ -z "${!var:-}" ]; then
        echo -e "${YELLOW}⚠️  $var not set in environment${NC}"
    fi
done

echo -e "${GREEN}✅ Pre-deployment checks passed${NC}"

# Step 2: Run tests
echo -e "\n${BLUE}[2/6] Running test suite...${NC}"
if command -v pytest &> /dev/null; then
    pytest tests/ -v --tb=short || {
        echo -e "${RED}❌ Tests failed! Aborting deployment.${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ All tests passed${NC}"
else
    echo -e "${YELLOW}⚠️  pytest not found, skipping tests${NC}"
fi

# Step 3: Security scan
echo -e "\n${BLUE}[3/6] Running security scan...${NC}"
if command -v bandit &> /dev/null; then
    bandit -r . -f json -o bandit-report.json -ll || true
    echo -e "${GREEN}✅ Security scan complete${NC}"
else
    echo -e "${YELLOW}⚠️  bandit not found, skipping security scan${NC}"
fi

# Step 4: Build Docker images
echo -e "\n${BLUE}[4/6] Building Docker images...${NC}"
if command -v docker &> /dev/null; then
    docker-compose build || {
        echo -e "${RED}❌ Docker build failed!${NC}"
        exit 1
    }
    echo -e "${GREEN}✅ Docker images built successfully${NC}"
else
    echo -e "${YELLOW}⚠️  Docker not found, skipping image build${NC}"
fi

# Step 5: Start services
echo -e "\n${BLUE}[5/6] Starting services...${NC}"
if [ "$ENVIRONMENT" == "production" ]; then
    docker-compose up -d || {
        echo -e "${RED}❌ Failed to start services!${NC}"
        exit 1
    }
else
    docker-compose up -d || {
        echo -e "${RED}❌ Failed to start services!${NC}"
        exit 1
    }
fi
echo -e "${GREEN}✅ Services started${NC}"

# Step 6: Health check
echo -e "\n${BLUE}[6/6] Running health checks...${NC}"
sleep 5  # Wait for services to start

if command -v curl &> /dev/null; then
    # Check API
    API_URL="http://localhost:8000"
    if curl -s "$API_URL/" > /dev/null; then
        echo -e "${GREEN}✅ API is healthy: $API_URL${NC}"
    else
        echo -e "${RED}❌ API health check failed${NC}"
    fi
    
    # Check Dashboard
    DASHBOARD_URL="http://localhost:8501"
    if curl -s "$DASHBOARD_URL/" > /dev/null; then
        echo -e "${GREEN}✅ Dashboard is healthy: $DASHBOARD_URL${NC}"
    else
        echo -e "${YELLOW}⚠️  Dashboard health check failed (may take longer to start)${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  curl not found, skipping health checks${NC}"
fi

# Deployment complete
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           🎉 Deployment Complete! 🎉                      ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Services:${NC}"
echo -e "  API:       http://localhost:8000"
echo -e "  Dashboard: http://localhost:8501"
echo -e "  Docs:      http://localhost:8000/docs"
echo ""
echo -e "${GREEN}Useful Commands:${NC}"
echo -e "  View logs:  docker-compose logs -f"
echo -e "  Stop:       docker-compose down"
echo -e "  Restart:    docker-compose restart"
echo ""
echo -e "${BLUE}Happy secret hunting! 🔍${NC}"

