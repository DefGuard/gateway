#!/usr/bin/env bash
set -e

echo "Updating apt repositories..."
sudo apt update

echo "Installing Defguard Gateway package..."
sudo dpkg -i /tmp/defguard-gateway.deb

echo "Cleaning up..."
sudo rm -f /tmp/defguard-gateway.deb

echo "Defguard Gateway installation completed successfully."
