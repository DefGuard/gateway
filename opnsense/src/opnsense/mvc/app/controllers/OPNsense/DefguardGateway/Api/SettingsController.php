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

    // public function getAction()
    // {
    //     // define list of configurable settings
    //     $result = [];
    //     if ($this->request->isGet()) {
    //         $mdlDefguardGateway = new DefguardGateway();
    //         $result["defguardgateway"] = $mdlDefguardGateway->getNodes();
    //     }
    //     return $result;
    // }

    // public function setAction()
    // {
    //     $result = ["result" => "failed"];
    //     if ($this->request->isPost()) {
    //         // load model and update with provided data
    //         $mdlDefguardGateway = new DefguardGateway();
    //         $mdlDefguardGateway->setNodes(
    //             $this->request->getPost("defguardgateway")
    //         );

    //         // perform validation
    //         $valMsgs = $mdlDefguardGateway->performValidation();
    //         foreach ($valMsgs as $field => $msg) {
    //             if (!array_key_exists("validations", $result)) {
    //                 $result["validations"] = [];
    //             }
    //             $result["validations"][
    //                 "defguardgateway." . $msg->getField()
    //             ] = $msg->getMessage();
    //         }

    //         // serialize model to config and save
    //         if ($valMsgs->count() == 0) {
    //             $mdlDefguardGateway->serializeToConfig();
    //             Config::getInstance()->save();
    //             $result["result"] = "saved";
    //         }
    //     }
    //     return $result;
    // }
}
