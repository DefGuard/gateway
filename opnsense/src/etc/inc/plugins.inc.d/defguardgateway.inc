<?php
function defguardgateway_services()
{
    $services = [];

    $pidfile = (string) (new OPNsense\DefguardGateway\DefguardGateway())->general->PidFile;

    $services[] = [
        "description" => "Defguard Gateway",
        "configd" => [
            "start" => ["defguard_gateway start"],
            "restart" => ["defguard_gateway restart"],
            "stop" => ["defguard_gateway stop"],
        ],
        "pidfile" => empty($pidfile) ? "/var/run/defguard_gateway.pid" : $pidfile,
        "name" => "defguard_gateway",
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

function defguardgateway_enabled()
{
    global $config;

    return isset($config['OPNsense']['defguardgateway']['general']['Enabled']) &&
    $config['OPNsense']['defguardgateway']['general']['Enabled'] == 1;
}

function defguardgateway_firewall($fw)
{
    if (!defguardgateway_enabled()) {
        return;
    }

    // $fw->registerAnchor('defguard/*', 'nat', 1, 'head');
    // $fw->registerAnchor('defguard/*', 'rdr', 1, 'head');
    $fw->registerAnchor('defguard/*', 'fw', 1, 'head', true);
}
