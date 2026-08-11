<?php
namespace OPNsense\DefguardGateway\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 * @package OPNsense\DefguardGateway
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceName = "defguardgateway";
    protected static $internalServiceClass = "\OPNsense\DefguardGateway\DefguardGateway";
    protected static $internalServiceTemplate = "OPNsense/DefguardGateway";
    protected static $internalServiceEnabled = "general.Enabled";

    /**
     * The 'defguard/*' anchor is hooked into the ruleset by defguardgateway_firewall().
     * Changes only take effect once the filter is reloaded.
     */
    protected function invokeFirewallReload()
    {
        return true;
    }
}
