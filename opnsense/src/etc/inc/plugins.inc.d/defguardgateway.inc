<?php
function defguardgateway_services()
{
    $services = [];

    $services[] = [
        "description" => "Defguard Gateway",
        "configd" => [
            "start" => ["defguard_gateway start"],
            "restart" => ["defguard_gateway restart"],
            "stop" => ["defguard_gateway stop"],
        ],
        "name" => "defguard_gateway",
        "nocheck" => true,
    ];

    return $services;
}

function defguardgateway_interfaces()
{
    $interfaces = [];

    $interfaces["defguard"] = [
        "descr" => gettext("Defguard (Group)"),
        "if" => "defguard",
        "virtual" => true,
        "enable" => true,
        "type" => "group",
        "networks" => [],
    ];

    return $interfaces;
}

function defguardgateway_devices()
{
    $names = [];

    $interface = (new OPNsense\DefguardGateway\DefguardGateway())->general
        ->IfName;

    $devices[] = [
        "function" => "defguard_prepare",
        "configurable" => false,
        "pattern" => "^wg",
        "type" => "wireguard",
        "volatile" => true,
        "names" => [
            (string) $interface => [
                "descr" => sprintf(
                    "%s (Defguard Gateway)",
                    (string) $interface
                ),
                "ifdescr" => "WireGuard interface used by Defguard Gateway",
                "name" => (string) $interface,
            ],
        ],
    ];

    return $devices;
}
