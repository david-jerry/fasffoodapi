#!/bin/bash

# Function to trap EXIT signal and terminate background jobs
cleanup() {
    echo "Shutting down background jobs..."
    # Send SIGTERM to all background jobs
    kill $(jobs -p)
}

# Trap EXIT signal and call cleanup function
trap cleanup EXIT

# Run mailpit in the background
~/mailpit/mailpit &

# Run server in the background
./run_async.py &

# Run Redis server in the background
if ! pgrep -x "redis-server" > /dev/null; then
    # If not running, start Redis server in the background
    redis-server &
fi

# send sample mail
./manage.py sendtestemail --admin &

# Run Celery beat and worker in the background
# celery -A config.celery_app beat &
# celery -A config.celery_app worker -B -l info &
celery -A config.celery_app worker -l info &


# Wait for all background jobs to finish
wait
