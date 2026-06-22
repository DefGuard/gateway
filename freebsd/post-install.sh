#!/bin/sh
CONFIG=/etc/defguard/gateway.toml

if [ ! -f "${CONFIG}" ]; then
	cp "${CONFIG}.sample" "${CONFIG}"
fi
