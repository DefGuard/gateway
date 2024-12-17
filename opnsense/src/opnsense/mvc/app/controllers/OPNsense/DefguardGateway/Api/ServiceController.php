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
}
