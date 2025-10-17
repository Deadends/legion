#!/bin/bash
# Health check script for monitoring

API_URL=${1:-http://localhost:3031}

echo "🏥 Legion Health Check"
echo "====================="
echo "API URL: $API_URL"
echo ""

# Check backend health
echo "Checking backend..."
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" $API_URL/health)

if [ "$HEALTH" = "200" ]; then
    echo "✅ Backend: Healthy"
else
    echo "❌ Backend: Unhealthy (HTTP $HEALTH)"
    exit 1
fi

# Check Redis
echo "Checking Redis..."
if command -v redis-cli &> /dev/null; then
    if redis-cli ping > /dev/null 2>&1; then
        echo "✅ Redis: Connected"
    else
        echo "❌ Redis: Disconnected"
        exit 1
    fi
else
    echo "⚠️  Redis: Cannot check (redis-cli not installed)"
fi

# Check disk space
echo "Checking disk space..."
DISK_USAGE=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -lt 80 ]; then
    echo "✅ Disk: ${DISK_USAGE}% used"
else
    echo "⚠️  Disk: ${DISK_USAGE}% used (high)"
fi

# Check memory
echo "Checking memory..."
if command -v free &> /dev/null; then
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    if [ "$MEM_USAGE" -lt 90 ]; then
        echo "✅ Memory: ${MEM_USAGE}% used"
    else
        echo "⚠️  Memory: ${MEM_USAGE}% used (high)"
    fi
fi

echo ""
echo "✅ All checks passed!"
