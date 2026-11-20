<?php
namespace OPNsense\DefguardGateway\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceName = "defguardgateway";
    protected static $internalServiceClass = "\OPNsense\DefguardGateway\DefguardGateway";
    protected static $internalServiceTemplate = "OPNsense/DefguardGateway";
    protected static $internalServiceEnabled = "general.Enabled";

    // Anchor changes from defguardgateway_firewall() apply only after a filter reload.
    protected function invokeFirewallReload()
    {
        return true;
    }
}
