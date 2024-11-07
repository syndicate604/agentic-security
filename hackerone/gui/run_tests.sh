#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Running tests for AI Hacker Fix GUI...${NC}\n"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${BLUE}Creating virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo -e "${BLUE}Installing dependencies...${NC}"
pip install -r requirements.txt
pip install pytest pytest-cov pytest-mock pytest-asyncio pytest-env

# Run tests with coverage
echo -e "\n${BLUE}Running tests...${NC}"
pytest \
    --verbose \
    --cov=. \
    --cov-report=term-missing \
    --cov-report=html \
    --durations=10 \
    test_*.py

# Check test exit code
if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
else
    echo -e "\n${RED}Some tests failed!${NC}"
    exit 1
fi

# Generate coverage badge
coverage_percentage=$(coverage report | grep TOTAL | awk '{print $NF}' | sed 's/%//')
echo -e "\n${BLUE}Coverage: ${coverage_percentage}%${NC}"

# Create coverage badge
echo "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100\" height=\"20\">
  <linearGradient id=\"b\" x2=\"0\" y2=\"100%\">
    <stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>
    <stop offset=\"1\" stop-opacity=\".1\"/>
  </linearGradient>
  <mask id=\"a\">
    <rect width=\"100\" height=\"20\" rx=\"3\" fill=\"#fff\"/>
  </mask>
  <g mask=\"url(#a)\">
    <path fill=\"#555\" d=\"M0 0h63v20H0z\"/>
    <path fill=\"#4c1\" d=\"M63 0h37v20H63z\"/>
    <path fill=\"url(#b)\" d=\"M0 0h100v20H0z\"/>
  </g>
  <g fill=\"#fff\" text-anchor=\"middle\" font-family=\"DejaVu Sans,Verdana,Geneva,sans-serif\" font-size=\"11\">
    <text x=\"31.5\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">coverage</text>
    <text x=\"31.5\" y=\"14\">coverage</text>
    <text x=\"81.5\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">${coverage_percentage}%</text>
    <text x=\"81.5\" y=\"14\">${coverage_percentage}%</text>
  </g>
</svg>" > coverage-badge.svg

# Generate test report
echo -e "\n${BLUE}Generating test report...${NC}"
cat << EOF > test-report.md
# Test Report

## Summary
- Total tests: $(pytest --collect-only -q | wc -l)
- Coverage: ${coverage_percentage}%
- Duration: $(pytest --durations=0 2>&1 | grep "seconds" | head -n 1 | awk '{print $NF}') seconds

## Coverage Report
\`\`\`
$(coverage report)
\`\`\`

## Test Details
\`\`\`
$(pytest -v)
\`\`\`

## Slow Tests (Top 10)
\`\`\`
$(pytest --durations=10 2>&1 | grep "seconds")
\`\`\`
EOF

echo -e "\n${BLUE}Test report generated: test-report.md${NC}"
echo -e "${BLUE}Coverage report generated: htmlcov/index.html${NC}"
echo -e "${BLUE}Coverage badge generated: coverage-badge.svg${NC}"

# Deactivate virtual environment
deactivate

echo -e "\n${GREEN}Testing completed!${NC}"
