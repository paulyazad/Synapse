#!/bin/bash
# Start the Synapse Next.js frontend
echo "Starting Synapse frontend on http://localhost:3000"
echo ""
cd "$(dirname "$0")/frontend"
npm run dev
