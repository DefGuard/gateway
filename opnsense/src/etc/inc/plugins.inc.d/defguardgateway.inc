<?php

function defguardgateway_general()
{
    return (new OPNsense\DefguardGateway\DefguardGateway())->general;
}

function defguardgateway_enabled()
{
    return (string) defguardgateway_general()->Enabled === '1';
}

function defguardgateway_services()
{
    if (!defguardgateway_enabled()) {
        return [];
    }

    return [[
        'description' => 'Defguard Gateway',
        'configd' => [
            'start' => ['defguardgateway start'],
            'restart' => ['defguardgateway restart'],
            'stop' => ['defguardgateway stop'],
        ],
        'pidfile' => (string) defguardgateway_general()->PidFile ?: '/var/run/defguard_gateway.pid',
        'name' => 'defguardgateway',
    ]];
}

function defguardgateway_interfaces()
{
    return [
        'defguard' => [
            'descr' => gettext('Defguard (Group)'),
            'if' => 'defguard',
            'virtual' => true,
            'enable' => true,
            'type' => 'group',
            'networks' => [],
        ],
    ];
}

function defguardgateway_devices()
{
    $interface = (string) defguardgateway_general()->IfName ?: 'wg0';

    return [[
        'configurable' => false,
        'pattern' => '^' . preg_quote($interface, '/') . '$',
        'type' => 'wireguard',
        'volatile' => true,
        'names' => [
            $interface => [
                'descr' => "{$interface} (Defguard Gateway)",
                'ifdescr' => 'WireGuard interface used by Defguard Gateway',
                'name' => $interface,
            ],
        ],
    ]];
}

function defguardgateway_firewall($fw)
{
    if (!defguardgateway_enabled()) {
        return;
    }

    $general = defguardgateway_general();
    $placement = (string) $general->FwAnchorPlacement ?: 'tail';
    // On FreeBSD 15+ (OPNsense 26.7+) a quick anchor skips OPNsense rules even when no inner rule matches.
    $quick = (string) $general->FwAnchorQuick === '1';
    $fw->registerAnchor('defguard/*', 'fw', 1, $placement, $quick);
}
