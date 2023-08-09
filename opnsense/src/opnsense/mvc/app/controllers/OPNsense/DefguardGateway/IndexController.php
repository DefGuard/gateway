<?php
namespace OPNsense\DefguardGateway;
class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        // pick the template to serve to our users.
        $this->view->pick('OPNsense/DefguardGateway/index');
	// fetch form data "general"
	$this->view->generalForm = $this->getForm("general");
    }
}
