<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Custom Zend_Controller_Request_Http class (formally)
 *
 * Allows dispatching before and after events for each controller action
 */
class Mage_Core_Controller_Request_Http extends Zend_Controller_Request_Http
{
    public const XML_NODE_DIRECT_FRONT_NAMES = 'global/request/direct_front_name';
    public const DEFAULT_HTTP_PORT = 80;
    public const DEFAULT_HTTPS_PORT = 443;

    /**
     * ORIGINAL_PATH_INFO
     * @var string
     */
    protected $_originalPathInfo = '';
    protected $_storeCode       = null;
    protected $_requestString   = '';

    /**
     * Path info array used before applying rewrite from config
     *
     * @var null|array
     */
    protected $_rewritedPathInfo = null;
    protected $_requestedRouteName = null;
    protected $_routingInfo = [];

    protected $_route;

    protected $_directFrontNames = null;
    protected $_controllerModule = null;

    /**
     * Streight request flag.
     * If flag is determined no additional logic is applicable
     *
     * @var bool $_isStraight
     */
    protected $_isStraight = false;

    /**
     * Request's original information before forward.
     *
     * @var array
     */
    protected $_beforeForwardInfo = [];

    /**
     * Flag for recognizing if request internally forwarded
     *
     * @var bool
     */
    protected $_internallyForwarded = false;

    /**
     * Returns ORIGINAL_PATH_INFO.
     * This value is calculated instead of reading PATH_INFO
     * directly from $_SERVER due to cross-platform differences.
     *
     * @return string 'something.html'|'/'|'/path0'|'/path0/path1/'|'/path0/path1/path2'|etc
     */
    public function getOriginalPathInfo()
    {
        if (empty($this->_originalPathInfo)) {
            $this->setPathInfo();
        }
        return $this->_originalPathInfo;
    }

    /**
     * @return string|null
     * @throws Mage_Core_Model_Store_Exception
     */
    public function getStoreCodeFromPath()
    {
        if (!$this->_storeCode) {
            // get store view code
            if ($this->_canBeStoreCodeInUrl()) {
                $p = explode('/', trim($this->getPathInfo(), '/'));
                $storeCode = $p[0];

                $stores = Mage::app()->getStores(true, true);

                if ($storeCode !== '' && isset($stores[$storeCode])) {
                    array_shift($p);
                    $this->setPathInfo(implode('/', $p));
                    $this->_storeCode = $storeCode;
                    Mage::app()->setCurrentStore($storeCode);
                } else {
                    $this->_storeCode = Mage::app()->getStore()->getCode();
                }
            } else {
                $this->_storeCode = Mage::app()->getStore()->getCode();
            }
        }
        return $this->_storeCode;
    }

    /**
     * Set the PATH_INFO string
     * Set the ORIGINAL_PATH_INFO string
     *
     * @param string|null $pathInfo
     * @return Zend_Controller_Request_Http
     */
    #[\Override]
    public function setPathInfo($pathInfo = null)
    {
        if ($pathInfo === null) {
            $requestUri = $this->getRequestUri();
            if ($requestUri === null) {
                return $this;
            }

            // Remove the query string from REQUEST_URI
            $pos = strpos($requestUri, '?');
            if ($pos) {
                $requestUri = substr($requestUri, 0, $pos);
            }

            $baseUrl = $this->getBaseUrl();
            $pathInfo = substr($requestUri, strlen($baseUrl));

            if ($baseUrl && $pathInfo && (stripos($pathInfo, '/') !== 0)) {
                $pathInfo = '';
                $this->setActionName('noRoute');
            } elseif ($baseUrl !== null && !$pathInfo) {
                $pathInfo = '';
            } elseif ($baseUrl === null) {
                $pathInfo = $requestUri;
            }

            if ($this->_canBeStoreCodeInUrl()) {
                $pathParts = explode('/', ltrim($pathInfo, '/'), 2);
                $storeCode = $pathParts[0];

                if (!$this->isDirectAccessFrontendName($storeCode)) {
                    $stores = Mage::app()->getStores(true, true);
                    if ($storeCode !== '' && isset($stores[$storeCode])) {
                        Mage::app()->setCurrentStore($storeCode);
                        $pathInfo = '/' . ($pathParts[1] ?? '');
                    } elseif ($storeCode !== '') {
                        $this->setActionName('noRoute');
                    }
                }
            }

            $this->_originalPathInfo = (string) $pathInfo;
            $this->_requestString = $pathInfo . ($pos !== false ? substr($requestUri, $pos) : '');
        }

        $this->_pathInfo = (string) $pathInfo;
        return $this;
    }

    /**
     * Specify new path info
     * It happen when occur rewrite based on configuration
     *
     * @param   string $pathInfo
     * @return  Mage_Core_Controller_Request_Http
     */
    public function rewritePathInfo($pathInfo)
    {
        if (($pathInfo != $this->getPathInfo()) && ($this->_rewritedPathInfo === null)) {
            $this->_rewritedPathInfo = explode('/', trim($this->getPathInfo(), '/'));
        }
        $this->setPathInfo($pathInfo);
        return $this;
    }

    /**
     * Check if can be store code as part of url
     *
     * @return bool
     */
    protected function _canBeStoreCodeInUrl()
    {
        return Mage::isInstalled() && Mage::getStoreConfigFlag(Mage_Core_Model_Store::XML_PATH_STORE_IN_URL);
    }

    /**
     * Check if code declared as direct access frontend name
     * this mean what this url can be used without store code
     *
     * @param   string $code
     * @return  bool
     */
    public function isDirectAccessFrontendName($code)
    {
        $names = $this->getDirectFrontNames();
        return isset($names[$code]);
    }

    /**
     * Get list of front names available with access without store code
     *
     * @return array
     */
    public function getDirectFrontNames()
    {
        if (is_null($this->_directFrontNames)) {
            $names = Mage::getConfig()->getNode(self::XML_NODE_DIRECT_FRONT_NAMES);
            if ($names) {
                $this->_directFrontNames = $names->asArray();
            } else {
                return [];
            }
        }
        return $this->_directFrontNames;
    }

    /**
     * @return Zend_Controller_Request_Http
     */
    public function getOriginalRequest()
    {
        $request = new Zend_Controller_Request_Http();
        $request->setPathInfo($this->getOriginalPathInfo());
        return $request;
    }

    /**
     * @return string
     */
    public function getRequestString()
    {
        return $this->_requestString;
    }

    /**
     * @return string
     */
    #[\Override]
    public function getBasePath()
    {
        $path = parent::getBasePath();
        if (empty($path)) {
            $path = '/';
        } else {
            $path = str_replace('\\', '/', $path);
        }
        return $path;
    }

    /**
     * @param bool $raw
     * @return string
     */
    #[\Override]
    public function getBaseUrl($raw = false)
    {
        $url = parent::getBaseUrl($raw);
        $url = str_replace('\\', '/', $url);
        return $url;
    }

    /**
     * @param string $route
     * @return $this
     */
    public function setRouteName($route)
    {
        $this->_route = $route;
        $router = Mage::app()->getFrontController()->getRouterByRoute($route);
        if (!$router) {
            return $this;
        }
        $module = $router->getFrontNameByRoute($route);
        if ($module) {
            $this->setModuleName($module);
        }
        return $this;
    }

    /**
     * @return string
     */
    public function getRouteName()
    {
        return $this->_route;
    }

    /**
     * Get the request URI scheme
     *
     * @return string
     */
    #[\Override]
    public function getScheme()
    {
        return $this->getServer('HTTPS') == 'on'
          || $this->getServer('HTTP_X_FORWARDED_PROTO') == 'https'
          || (Mage::isInstalled() && Mage::app()->isCurrentlySecure()) ?
            self::SCHEME_HTTPS :
            self::SCHEME_HTTP;
    }

    /**
     * Retrieve HTTP HOST
     *
     * @param bool $trimPort
     * @return false|string
     */
    #[\Override]
    public function getHttpHost($trimPort = true)
    {
        if (!isset($_SERVER['HTTP_HOST'])) {
            return false;
        }
        $host = $_SERVER['HTTP_HOST'];
        if ($trimPort) {
            $hostParts = explode(':', $_SERVER['HTTP_HOST']);
            $host =  $hostParts[0];
        }

        if (str_contains($host, ',') || str_contains($host, ';')) {
            $response = new Zend_Controller_Response_Http();
            $response->setHttpResponseCode(400)->sendHeaders();
            exit();
        }

        return $host;
    }

    /**
     * Set a member of the $_POST superglobal
     *
     * @param string|array $key
     * @param mixed $value
     * @return $this
     */
    #[\Override]
    public function setPost($key, $value = null)
    {
        if (is_array($key)) {
            $_POST = $key;
        } else {
            $_POST[$key] = $value;
        }
        return $this;
    }

    /**
     * Specify module name where was found currently used controller
     *
     * @param   string $module
     * @return  Mage_Core_Controller_Request_Http
     */
    public function setControllerModule($module)
    {
        $this->_controllerModule = $module;
        return $this;
    }

    /**
     * Get module name of currently used controller
     *
     * @return  string
     */
    public function getControllerModule()
    {
        return $this->_controllerModule;
    }

    /**
     * Retrieve the module name
     *
     * @return string
     */
    #[\Override]
    public function getModuleName()
    {
        return $this->_module;
    }
    /**
     * Retrieve the controller name
     *
     * @return string
     */
    #[\Override]
    public function getControllerName()
    {
        return $this->_controller;
    }
    /**
     * Retrieve the action name
     *
     * @return string
     */
    #[\Override]
    public function getActionName()
    {
        return $this->_action;
    }

    /**
     * Retrieve an alias
     *
     * Retrieve the actual key represented by the alias $name.
     *
     * @param string $name
     * @return string|null Returns null when no alias exists
     */
    #[\Override]
    public function getAlias($name)
    {
        $aliases = $this->getAliases();
        return $aliases[$name] ?? null;
    }

    /**
     * Retrieve the list of all aliases
     *
     * @return array
     */
    #[\Override]
    public function getAliases()
    {
        return $this->_routingInfo['aliases'] ?? parent::getAliases();
    }

    /**
     * Get route name used in request (ignore rewrite)
     *
     * @return string
     */
    public function getRequestedRouteName()
    {
        if (isset($this->_routingInfo['requested_route'])) {
            return $this->_routingInfo['requested_route'];
        }
        if ($this->_requestedRouteName === null) {
            if ($this->_rewritedPathInfo !== null && isset($this->_rewritedPathInfo[0])) {
                $fronName = $this->_rewritedPathInfo[0];
                $router = Mage::app()->getFrontController()->getRouterByFrontName($fronName);
                $this->_requestedRouteName = $router->getRouteByFrontName($fronName);
            } else {
                // no rewritten path found, use default route name
                return $this->getRouteName();
            }
        }
        return $this->_requestedRouteName;
    }

    /**
     * Get controller name used in request (ignore rewrite)
     *
     * @return string
     */
    public function getRequestedControllerName()
    {
        if (isset($this->_routingInfo['requested_controller'])) {
            return $this->_routingInfo['requested_controller'];
        }
        if (($this->_rewritedPathInfo !== null) && isset($this->_rewritedPathInfo[1])) {
            return $this->_rewritedPathInfo[1];
        }
        return $this->getControllerName();
    }

    /**
     * Get action name used in request (ignore rewrite)
     *
     * @return string
     */
    public function getRequestedActionName()
    {
        if (isset($this->_routingInfo['requested_action'])) {
            return $this->_routingInfo['requested_action'];
        }
        if (($this->_rewritedPathInfo !== null) && isset($this->_rewritedPathInfo[2])) {
            return $this->_rewritedPathInfo[2];
        }
        return $this->getActionName();
    }

    /**
     * Set routing info data
     *
     * @param array $data
     * @return $this
     */
    public function setRoutingInfo($data)
    {
        if (is_array($data)) {
            $this->_routingInfo = $data;
        }
        return $this;
    }

    /**
     * Collect properties changed by _forward in protected storage
     * before _forward was called first time.
     *
     * @return $this
     */
    public function initForward()
    {
        if (empty($this->_beforeForwardInfo)) {
            $this->_beforeForwardInfo = [
                'params' => $this->getParams(),
                'action_name' => $this->getActionName(),
                'controller_name' => $this->getControllerName(),
                'module_name' => $this->getModuleName(),
            ];
        }

        return $this;
    }

    /**
     * Retrieve property's value which was before _forward call.
     * If property was not changed during _forward call null will be returned.
     * If passed name will be null whole state array will be returned.
     *
     * @param string $name
     * @return array|string|null
     */
    public function getBeforeForwardInfo($name = null)
    {
        if (is_null($name)) {
            return $this->_beforeForwardInfo;
        } elseif (isset($this->_beforeForwardInfo[$name])) {
            return $this->_beforeForwardInfo[$name];
        }

        return null;
    }

    /**
     * Specify/get _isStraight flag value
     *
     * @param bool $flag
     * @return bool
     */
    public function isStraight($flag = null)
    {
        if ($flag !== null) {
            $this->_isStraight = $flag;
        }
        return $this->_isStraight;
    }

    /**
     * Check is Request from AJAX
     *
     * @return bool
     */
    public function isAjax()
    {
        if ($this->isXmlHttpRequest()) {
            return true;
        }
        if ($this->getParam('ajax') || $this->getParam('isAjax')) {
            return true;
        }
        return false;
    }

    /**
     * Define that request was forwarded internally
     *
     * @param bool $flag
     * @return $this
     */
    public function setInternallyForwarded($flag = true)
    {
        $this->_internallyForwarded = (bool) $flag;
        return $this;
    }

    /**
     * Checks if request was forwarded internally
     *
     * @return bool
     */
    public function getInternallyForwarded()
    {
        return $this->_internallyForwarded;
    }
}
