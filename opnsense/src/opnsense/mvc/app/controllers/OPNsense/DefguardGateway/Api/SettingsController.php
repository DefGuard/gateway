<?php
namespace OPNsense\DefguardGateway\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

/**
 * Class SettingsController Handles settings related API actions for the DefguardGateway module
 * @package OPNsense\DefguardGateway
 */
class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = "\OPNsense\DefguardGateway\DefguardGateway";
    protected static $internalModelName = "defguardgateway";
}
