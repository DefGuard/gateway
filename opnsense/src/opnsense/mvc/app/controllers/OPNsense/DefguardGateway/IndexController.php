<?php
namespace OPNsense\DefguardGateway;
class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick("OPNsense/DefguardGateway/index");
        $this->view->generalForm = $this->getForm("general");
    }
}
