<?php
namespace OPNsense\DefguardGateway\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 * @package OPNsense\DefguardGateway
 */
class ServiceController extends ApiControllerBase
{
    /**
     * reconfigure DefguardGateway
     */

    public function reloadAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $backend = new Backend();
            $bckresult = trim(
                $backend->configdRun("template reload OPNsense/DefguardGateway")
            );
            if ($bckresult == "OK") {
                $status = "Configuration saved to /etc/defguard/gateway.toml";
            }
        }
        return ["status" => $status];
    }
    public function resetAction()
    {
        $backend = new Backend();
        $result = trim($backend->configdRun("defguardgateway restart"));
        return ["status" => $result];
    }
}
