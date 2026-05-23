#!/bin/bash
# Start the Synapse Flask API
# Requires: pip install -r synapse/api/requirements.txt
# The trained model (soc_models_v4.pkl) must exist alongside soc_analyst.py

echo "Starting Synapse API on http://localhost:5050"
echo ""
echo "  Model expected at: ../soc_models_v4.pkl"
echo "  Log written to:    ../prediction_log_v4.csv"
echo ""
echo "  Set VT API key (optional):"
echo "    export VT_API_KEY='your_key_here'"
echo ""
cd "$(dirname "$0")"
python api/app.py
