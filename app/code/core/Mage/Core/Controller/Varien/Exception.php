<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2018-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Core_Controller_Varien_Exception extends Exception
{
    public const RESULT_FORWARD  = '_forward';
    public const RESULT_REDIRECT = '_redirect';

    protected $_resultCallback       = null;
    protected $_resultCallbackParams = [];
    protected $_defaultActionName    = 'noroute';
    protected $_flags                = [];

    /**
     * Prepare data for forwarding action
     *
     * @param string $actionName
     * @param string $controllerName
     * @param string $moduleName
     * @return $this
     */
    public function prepareForward($actionName = null, $controllerName = null, $moduleName = null, array $params = [])
    {
        $this->_resultCallback = self::RESULT_FORWARD;
        if ($actionName === null) {
            $actionName = $this->_defaultActionName;
        }
        $this->_resultCallbackParams = [$actionName, $controllerName, $moduleName, $params];
        return $this;
    }

    /**
     * Prepare data for redirecting
     *
     * @param string $path
     * @param array $arguments
     * @return $this
     */
    public function prepareRedirect($path, $arguments = [])
    {
        $this->_resultCallback = self::RESULT_REDIRECT;
        $this->_resultCallbackParams = [$path, $arguments];
        return $this;
    }

    /**
     * Prepare data for running a custom action
     *
     * @param string $actionName
     * @return $this
     */
    public function prepareFork($actionName = null)
    {
        if ($actionName === null) {
            $actionName = $this->_defaultActionName;
        }
        $this->_resultCallback = $actionName;
        return $this;
    }

    /**
     * Prepare a flag data
     *
     * @param string $action
     * @param string $flag
     * @param bool $value
     * @return $this
     */
    public function prepareFlag($action, $flag, $value)
    {
        $this->_flags[] = [$action, $flag, $value];
        return $this;
    }

    /**
     * Return all set flags
     *
     * @return array
     */
    public function getResultFlags()
    {
        return $this->_flags;
    }

    /**
     * Return results as callback for a controller
     *
     * @return array
     */
    public function getResultCallback()
    {
        if ($this->_resultCallback === null) {
            $this->prepareFork();
        }
        return [$this->_resultCallback, $this->_resultCallbackParams];
    }
}
