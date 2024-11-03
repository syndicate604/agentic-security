#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Environment setup
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
if [ -f ".env" ]; then
  source .env
fi

# Run security pipeline
echo "Running security pipeline..."
python3 -m agentic_security.security_cli run --config config.yml

echo "Pipeline execution completed successfully!"
