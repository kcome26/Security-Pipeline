#!/bin/bash
# Initialize MobSF on EC2 instance

set -e

echo "Installing dependencies..."
apt-get update
apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    docker.io \
    docker-compose \
    git

echo "Installing MobSF..."
pip3 install --upgrade pip
pip3 install mobsf

echo "Creating MobSF directories..."
mkdir -p /opt/mobsf
cd /opt/mobsf

echo "Starting MobSF service..."
python3 -m mobsf.MobSF 0.0.0.0:8000 &

echo "MobSF initialization complete"
