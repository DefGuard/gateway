<?php
function defguardgateway_services()
{
    global $config;

    $services = [];

    $pidfile = (string) (new OPNsense\DefguardGateway\DefguardGateway())->general->PidFile;

    if (isset($config['OPNsense']['defguardgateway']['general']['Enabled']) && $config['OPNsense']['defguardgateway']['general']['Enabled'] == 1) {
        $services[] = [
            "description" => "Defguard Gateway",
            "configd" => [
                "start" => ["defguardgateway start"],
                "restart" => ["defguardgateway restart"],
                "stop" => ["defguardgateway stop"],
            ],
            "pidfile" => empty($pidfile) ? "/var/run/defguard_gateway.pid" : $pidfile,
            "name" => "defguardgateway",
        ];
    }

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
    $interface = (new OPNsense\DefguardGateway\DefguardGateway())->general
        ->IfName;
    $interface = empty((string) $interface) ? 'wg0' : (string) $interface;

    $devices[] = [
        "configurable" => false,
        "pattern" => sprintf("^%s$", preg_quote($interface, '/')),
        "type" => "wireguard",
        "volatile" => true,
        "names" => [
            $interface => [
                "descr" => sprintf(
                    "%s (Defguard Gateway)",
                    $interface
                ),
                "ifdescr" => "WireGuard interface used by Defguard Gateway",
                "name" => $interface,
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
    // IMPORTANT: never register this anchor as 'quick'. On FreeBSD 15+
    // (OPNsense 26.7+), a 'quick' anchor short-circuits the parent ruleset
    // even when no inner rule matches, silently skipping OPNsense's own
    // firewall rules.
    $model = new OPNsense\DefguardGateway\DefguardGateway();
    $placement = (string) $model->general->FwAnchorPlacement ?: 'tail';
    $quick = (string) $model->general->FwAnchorQuick === '1';
    $fw->registerAnchor('defguard/*', 'fw', 1, $placement, $quick);
}
