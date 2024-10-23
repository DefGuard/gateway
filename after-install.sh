if systemctl is-enabled defguard-gateway --quiet; then
    systemctl restart defguard-gateway
fi
