<?php

/*
 * Copyright (C) 2015-2022 Deciso B.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\Base;

use OPNsense\Core\ACL;
use OPNsense\Auth\AuthenticationFactory;

/**
 * Class ApiControllerBase, inherit this class to implement API calls
 * @package OPNsense\Base
 */
class ApiControllerBase extends ControllerRoot
{
    /***
     * Recordset (array in array) search wrapper
     * @param string $path path to search, relative to this model
     * @param array $fields fieldnames to search through in result
     * @param string|null $defaultSort default sort field name
     * @param null|function $filter_funct additional filter callable
     * @param int $sort_flags sorting behavior
     * @return array
     */
    protected function searchRecordsetBase(
        $records,
        $fields = null,
        $defaultSort = null,
        $filter_funct = null,
        $sort_flags = SORT_NATURAL | SORT_FLAG_CASE
    ) {
        $records = is_array($records) ? $records : []; // safeguard input, we are only able to search arrays.
        $itemsPerPage = intval($this->request->getPost('rowCount', 'int', 9999));
        $itemsPerPage = $itemsPerPage == -1 ? count($records) : $itemsPerPage;
        $currentPage = intval($this->request->getPost('current', 'int', 1));
        $offset = ($currentPage - 1) * $itemsPerPage;
        $entry_keys = array_keys($records);
        $searchPhrase = (string)$this->request->getPost('searchPhrase', null, '');

        if (
            $this->request->hasPost('sort') &&
            is_array($this->request->getPost('sort')) &&
            !empty($this->request->getPost('sort'))
        ) {
            $keys = array_keys($this->request->getPost('sort'));
            $order = $this->request->getPost('sort')[$keys[0]];
            $keys = array_column($records, $keys[0]);
            if (!empty($keys)) {
                array_multisort($keys, $order == 'asc' ? SORT_ASC : SORT_DESC, $sort_flags, $records);
            }
        } elseif (!empty($defaultSort)) {
            $keys = array_column($records, $defaultSort);
            if (!empty($keys)) {
                array_multisort($keys, SORT_ASC, $sort_flags, $records);
            }
        }

        $entry_keys = array_filter($entry_keys, function ($key) use ($searchPhrase, $filter_funct, $fields, $records) {
            if (is_callable($filter_funct) && !$filter_funct($records[$key])) {
                // not applicable according to $filter_funct()
                return false;
            } elseif (!empty($searchPhrase)) {
                foreach ($records[$key] as $itemkey => $itemval) {
                    if (
                        !is_array($itemval) &&
                        stripos((string)$itemval, $searchPhrase) !== false &&
                        (empty($fields) || in_array($itemkey, $fields))
                    ) {
                        return true;
                    }
                }
                return false;
            } else {
                return true;
            }
        });

        $formatted = array_map(function ($value) use (&$records) {
            foreach ($records[$value] as $ekey => $evalue) {
                $item[$ekey] = $evalue;
            }
            return $item;
        }, array_slice($entry_keys, $offset, $itemsPerPage));

        return [
           'total' => count($entry_keys),
           'rowCount' => count($formatted),
           'current' => $currentPage,
           'rows' => $formatted,
        ];
    }

    /**
     * parse raw json type content to POST data depending on content type
     * (only for api calls)
     * @return string
     */
    private function parseJsonBodyData()
    {
        switch (strtolower(str_replace(' ', '', $this->request->getHeader('CONTENT_TYPE')))) {
            case 'application/json':
            case 'application/json;charset=utf-8':
                $jsonRawBody = $this->request->getJsonRawBody(true);
                if (empty($this->request->getRawBody()) && empty($jsonRawBody)) {
                    return "Invalid JSON syntax";
                }
                $_POST = is_array($jsonRawBody) ? $jsonRawBody : [];
                foreach ($_POST as $key => $value) {
                    $_REQUEST[$key] = $value;
                }
                break;
            case 'application/x-www-form-urlencoded':
            case 'application/x-www-form-urlencoded;charset=utf-8':
                // valid non parseable content
                break;
            default:
                if (!empty($this->request->getRawBody())) {
                    $this->getLogger()->warning('unparsable Content-Type:' . $this->request->getHeader('CONTENT_TYPE') . ' received');
                }
                break;
        }
        return null;
    }

    /**
     * Raise errors, warnings, notices, etc.
     * @param $errno The first parameter, errno, contains the level of the
     *               error raised, as an integer.
     * @param $errstr The second parameter, errstr, contains the error
     *                message, as a string.
     * @param $errfile The third parameter is optional, errfile, which
     *                 contains the filename that the error was raised in, as
     *                 a string.
     * @param $errline The fourth parameter is optional, errline, which
     *                 contains the line number the error was raised at, as an
     *                 integer.
     * @throws \Exception
     */
    public function APIErrorHandler($errno, $errstr, $errfile, $errline)
    {
        if ($errno & error_reporting()) {
            $msg = "Error at $errfile:$errline - $errstr (errno=$errno)";
            throw new \Exception($msg);
        }
    }

    /**
     * Initialize API controller
     */
    public function initialize()
    {
        // disable view processing
        set_error_handler(array($this, 'APIErrorHandler'));
    }

    /**
     * is external client (other then session authenticated)
     * @return bool
     */
    protected function isExternalClient()
    {
        return !empty($this->request->getHeader('Authorization'));
    }

    /**
     * before routing event.
     * Handles authentication and authentication of user requests
     * In case of API calls, also prevalidates if request can be executed to return a more readable response
     * to the user.
     * @param Dispatcher $dispatcher
     * @return null|bool
     */
    public function beforeExecuteRoute($dispatcher)
    {
        // handle authentication / authorization
        if ($this->isExternalClient()) {
            // Authorization header send, handle API request
            $authHeader = explode(' ', $this->request->getHeader('Authorization'));
            if (count($authHeader) > 1) {
                $key_secret_hash = $authHeader[1];
                $key_secret = explode(':', base64_decode($key_secret_hash));
                if (count($key_secret) > 1) {
                    $apiKey = $key_secret[0];
                    $apiSecret = $key_secret[1];

                    $authFactory = new AuthenticationFactory();
                    $authenticator = $authFactory->get("Local API");
                    if ($authenticator->authenticate($apiKey, $apiSecret)) {
                        $authResult = $authenticator->getLastAuthProperties();
                        if (array_key_exists('username', $authResult)) {
                            // check ACL if user is returned by the Authenticator object
                            $acl = new ACL();
                            if (!$acl->isPageAccessible($authResult['username'], $_SERVER['REQUEST_URI'])) {
                                $this->getLogger()->error("uri " . $_SERVER['REQUEST_URI'] .
                                    " not accessible for user " . $authResult['username'] . " using api key " .
                                    $apiKey);
                                // not authenticated
                                $this->response->setStatusCode(403, "Forbidden");
                                $this->response->setContentType('application/json', 'UTF-8');
                                $this->response->setJsonContent(['status'  => 403,'message' => 'Forbidden']);
                                $this->response->send();
                                return false;
                            } else {
                                // authentication + authorization successful.
                                // pre validate request and communicate back to the user on errors
                                $callMethodName = $dispatcher->getActionName() . 'Action';
                                $dispatchError = null;
                                // check number of parameters using reflection
                                $object_info = new \ReflectionObject($this);
                                if ($object_info->hasMethod($callMethodName)) {
                                    // only inspect parameters if object exists
                                    $req_c = $object_info->getMethod($callMethodName)->getNumberOfRequiredParameters();
                                    if ($req_c > count($dispatcher->getParams())) {
                                        $dispatchError = 'action ' . $dispatcher->getActionName() .
                                            ' expects at least ' . $req_c . ' parameter(s)';
                                    }
                                }
                                // if body is send as json data, parse to $_POST first
                                $dispatchError = empty($dispatchError) ? $this->parseJsonBodyData() : $dispatchError;

                                if ($dispatchError != null) {
                                    // send error to client
                                    $this->response->setStatusCode(400, "Bad Request");
                                    $this->response->setContentType('application/json', 'UTF-8');
                                    $this->response->setJsonContent(
                                        array('message' => $dispatchError,
                                            'status'  => 400)
                                    );
                                    $this->response->send();
                                    return false;
                                }

                                // link username on successful login
                                $this->logged_in_user = $authResult['username'];

                                return true;
                            }
                        }
                    } else {
                        $this->getLogger()->error("uri " . $_SERVER['REQUEST_URI'] .
                            " authentication failed for api key " . $apiKey);
                    }
                }
            }
            // not authenticated
            $this->response->setStatusCode(401, "Unauthorized");
            $this->response->setContentType('application/json', 'UTF-8');
            $this->response->setJsonContent(['status'  => 401, 'message' => 'Authentication Failed']);
            $this->response->send();
            return false;
        } else {
            // handle UI ajax requests
            // use session data and ACL to validate request.
            if (!$this->doAuth()) {
                if (!$this->session->has("Username")) {
                    $this->response->setStatusCode(401, "Unauthorized");
                } else {
                    $this->response->setStatusCode(403, "Forbidden");
                }
                return false;
            }

            // check for valid csrf on post requests
            $csrf_token = $this->request->getHeader('X_CSRFTOKEN');
            $csrf_valid = $this->security->checkToken(null, $csrf_token, false);

            if (
                ($this->request->isPost() ||
                    $this->request->isPut() ||
                    $this->request->isDelete()
                ) && !$csrf_valid
            ) {
                // missing csrf, exit.
                $this->getLogger()->error("no matching csrf found for request");
                $this->response->setStatusCode(403, "Forbidden");
                return false;
            }
            // when request is using a json body (based on content type), parse it first
            $this->parseJsonBodyData();

            // link username on successful login
            $this->logged_in_user = $this->session->get("Username");
        }
    }

    /**
     * process API results, serialize return data to json.
     * @param $dispatcher
     * @return string json data
     */
    public function afterExecuteRoute($dispatcher)
    {
        // exit when reponse headers are already set
        if ($this->response->getHeaders()->get("Status") != null) {
            return false;
        } else {
            // process response, serialize to json object
            $data = $dispatcher->getReturnedValue();
            if (is_array($data)) {
                $this->response->setContentType('application/json', 'UTF-8');
                if ($this->isExternalClient()) {
                    $this->response->setContent(json_encode($data));
                } else {
                    $this->response->setContent(htmlspecialchars(json_encode($data), ENT_NOQUOTES));
                }
            }
        }

        return $this->response->send();
    }
}
