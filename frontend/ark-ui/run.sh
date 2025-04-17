#!/bin/bash

# Function to handle termination and clean up child processes
cleanup() {
    echo "Stopping servers..."
    if ps -p $BACKEND_PID > /dev/null; then
        kill $BACKEND_PID
    fi
    if ps -p $FRONTEND_PID > /dev/null; then
        kill $FRONTEND_PID
    fi

    exit 0
}

# Trap SIGINT to ensure cleanup function is called
trap cleanup SIGINT

# Navigate to the backend directory and start the backend server
echo "Starting backend..."
cd backend
npm start &
BACKEND_PID=$!

# Navigate to the frontend directory and start the frontend server
echo "Starting frontend..."
cd ../ark-ui
npm run serve &
FRONTEND_PID=$!

# Wait for a few seconds to ensure the servers are up and running
sleep 5

# Open the default web browser to http://localhost:8080
echo "Opening web browser to http://localhost:8080"
xdg-open http://localhost:8080

# Wait for all processes to end
wait $BACKEND_PID
wait $FRONTEND_PID
