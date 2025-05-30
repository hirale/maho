<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2017-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Core_Model_Design_Package
{
    public const DEFAULT_AREA    = Mage_Core_Model_App_Area::AREA_FRONTEND;
    public const DEFAULT_PACKAGE = 'default';
    public const DEFAULT_THEME   = 'default';
    public const BASE_PACKAGE    = 'base';

    /**
     * @deprecated after 1.4.0.0-alpha3
     */
    public const FALLBACK_THEME  = 'default';

    private static $_regexMatchCache      = [];
    private static $_customThemeTypeCache = [];

    /**
     * Current Store for generation ofr base_dir and base_url
     *
     * @var string|integer|Mage_Core_Model_Store
     */
    protected $_store = null;

    /**
     * Package area
     *
     * @var string|null
     */
    protected $_area;

    /**
     * Package name
     *
     * @var string
     */
    protected $_name;

    /**
     * Package theme
     *
     * @var array
     */
    protected $_theme;

    /**
     * Package root directory
     *
     * @var string
     */
    protected $_rootDir;

    /**
     * Directory of the css file
     * Using only to transmit additional parameter in callback functions
     * @var string
     */
    protected $_callbackFileDir;

    /**
     * @var Mage_Core_Model_Design_Config|null
     */
    protected $_config = null;

    /**
     * @var Mage_Core_Model_Design_Fallback|null
     */
    protected $_fallback = null;

    /**
     * Whether theme/skin hierarchy should be checked via fallback mechanism
     * @TODO: implement setter for this value
     * @var bool
     */
    protected $_shouldFallback = true;

    public function __construct()
    {
        if (is_null($this->_config)) {
            $this->_config = Mage::getSingleton('core/design_config');
        }
        if (is_null($this->_fallback)) {
            $this->_fallback = Mage::getSingleton('core/design_fallback', [
                'config' => $this->_config,
            ]);
        }
    }

    /**
     * Set store
     *
     * @param  string|int|Mage_Core_Model_Store $store
     * @return $this
     */
    public function setStore($store)
    {
        if ($this->_fallback) {
            $this->_fallback->setStore($store);
        }
        $this->_store = $store;
        return $this;
    }

    /**
     * Retrieve store
     *
     * @return string|integer|Mage_Core_Model_Store
     */
    public function getStore()
    {
        return $this->_store ?? Mage::app()->getStore();
    }

    /**
     * Set package area
     *
     * @param  string $area
     * @return $this
     */
    public function setArea($area)
    {
        $this->_area = $area;
        return $this;
    }

    /**
     * Retrieve package area
     *
     * @return string
     */
    public function getArea()
    {
        if (is_null($this->_area)) {
            $this->_area = self::DEFAULT_AREA;
        }
        return $this->_area;
    }

    /**
     * Set package name
     * In case of any problem, the default will be set.
     *
     * @param  string $name
     * @return $this
     */
    public function setPackageName($name = '')
    {
        if (empty($name)) {
            // see, if exceptions for user-agents defined in config
            $customPackage = $this->_checkUserAgentAgainstRegexps('design/package/ua_regexp');
            if ($customPackage) {
                $this->_name = $customPackage;
            } else {
                $this->_name = Mage::getStoreConfig('design/package/name', $this->getStore());
            }
        } else {
            $this->_name = $name;
        }
        // make sure not to crash, if wrong package specified
        if (!$this->designPackageExists($this->_name, $this->getArea())) {
            $this->_name = self::DEFAULT_PACKAGE;
        }
        return $this;
    }

    /**
     * Set store/package/area at once, and get respective values, that were before
     *
     * $storePackageArea must be assoc array. The keys may be:
     * 'store', 'package', 'area'
     *
     * @param array $storePackageArea
     * @return array
     */
    public function setAllGetOld($storePackageArea)
    {
        $oldValues = [];
        if (array_key_exists('store', $storePackageArea)) {
            $oldValues['store'] = $this->getStore();
            $this->setStore($storePackageArea['store']);
        }
        if (array_key_exists('area', $storePackageArea)) {
            $oldValues['area'] = $this->getArea();
            $this->setArea($storePackageArea['area']);
        }
        if (array_key_exists('package', $storePackageArea)) {
            $oldValues['package'] = $this->getPackageName();
            $this->setPackageName($storePackageArea['package']);
        }
        return $oldValues;
    }

    /**
     * Retrieve package name
     *
     * @return string
     */
    public function getPackageName()
    {
        if ($this->_name === null) {
            $this->setPackageName();
        }
        return $this->_name;
    }

    /**
     * @param string $packageName
     * @param string $area
     * @return bool
     */
    public function designPackageExists($packageName, $area = self::DEFAULT_AREA)
    {
        return true;
    }

    /**
     * Declare design package theme params
     * Polymorph method:
     * 1) if 1 parameter specified, sets everything to this value
     * 2) if 2 parameters, treats 1st as key and 2nd as value
     *
     * @return $this
     */
    public function setTheme()
    {
        switch (func_num_args()) {
            case 1:
                foreach (['layout', 'template', 'skin', 'locale', 'default'] as $type) {
                    $this->_theme[$type] = func_get_arg(0);
                }
                break;

            case 2:
                $this->_theme[func_get_arg(0)] = func_get_arg(1);
                break;

            default:
                throw Mage::exception(Mage::helper('core')->__('Wrong number of arguments for %s', __METHOD__));
        }
        return $this;
    }

    /**
     * @param string $type
     * @return string
     */
    public function getTheme($type)
    {
        if (empty($this->_theme[$type])) {
            $this->_theme[$type] = Mage::getStoreConfig('design/theme/' . $type, $this->getStore());
            if ($type !== 'default' && empty($this->_theme[$type])) {
                $this->_theme[$type] = $this->getTheme('default');
                if (empty($this->_theme[$type])) {
                    $this->_theme[$type] = self::DEFAULT_THEME;
                }
            }
        }

        // + "default", "skin"

        // set exception value for theme, if defined in config
        $customThemeType = $this->_checkUserAgentAgainstRegexps("design/theme/{$type}_ua_regexp");
        if ($customThemeType) {
            $this->_theme[$type] = $customThemeType;
        }

        return $this->_theme[$type];
    }

    /**
     * @return string
     */
    public function getDefaultTheme()
    {
        return self::DEFAULT_THEME;
    }

    /**
     * @return $this
     */
    public function updateParamDefaults(array &$params)
    {
        if ($this->getStore()) {
            $params['_store'] = $this->getStore();
        }
        if (empty($params['_area'])) {
            $params['_area'] = $this->getArea();
        }
        if (empty($params['_package'])) {
            $params['_package'] = $this->getPackageName();
        }
        if (empty($params['_theme'])) {
            $params['_theme'] = $this->getTheme($params['_type'] ?? '');
        }
        if (empty($params['_default'])) {
            $params['_default'] = false;
        }
        return $this;
    }

    /**
     * @return string
     */
    public function getBaseDir(array $params)
    {
        $this->updateParamDefaults($params);
        return (empty($params['_relative']) ? Mage::getBaseDir('design') . DS : '') .
            $params['_area'] . DS . $params['_package'] . DS . $params['_theme'] . DS . $params['_type'];
    }

    /**
     * @return string
     */
    public function getSkinBaseDir(array $params = [])
    {
        $params['_type'] = 'skin';
        $this->updateParamDefaults($params);
        return (empty($params['_relative']) ? Mage::getBaseDir('skin') . DS : '') .
            $params['_area'] . DS . $params['_package'] . DS . $params['_theme'];
    }

    /**
     * @return string
     */
    public function getLocaleBaseDir(array $params = [])
    {
        $params['_type'] = 'locale';
        $this->updateParamDefaults($params);
        return (empty($params['_relative']) ? Mage::getBaseDir('design') . DS : '') .
            $params['_area'] . DS . $params['_package'] . DS . $params['_theme'] . DS . 'locale' . DS .
            Mage::app()->getLocale()->getLocaleCode();
    }

    /**
     * @return string
     */
    public function getSkinBaseUrl(array $params = [])
    {
        $params['_type'] = 'skin';
        $this->updateParamDefaults($params);
        $urlPath = $params['_area'] . '/' . $params['_package'] . '/' . $params['_theme'] . '/';
        // Prevent XSS through malformed configuration
        $urlPath = htmlspecialchars($urlPath, ENT_HTML5 | ENT_QUOTES, 'UTF-8');
        return Mage::getBaseUrl('skin', isset($params['_secure']) ? (bool) $params['_secure'] : null) . $urlPath;
    }

    /**
     * Check whether requested file exists in specified theme params
     *
     * Possible params:
     * - _type: layout|template|skin|locale
     * - _package: design package, if not set = default
     * - _theme: if not set = default
     * - _file: path relative to theme root
     *
     * @see Mage_Core_Model_Config::getBaseDir
     * @param string $file
     * @return string|false
     */
    public function validateFile($file, array $params)
    {
        $fileName = $this->_renderFilename($file, $params);
        $fileName = (empty($params['_relative']) ? '' : Mage::getBaseDir('design') . DS) . $fileName;
        $fileName = Maho::findFile($fileName);
        return $fileName;
    }

    /**
     * Get filename by specified theme parameters
     *
     * @param string $file
     * @return string
     */
    protected function _renderFilename($file, array $params)
    {
        $dir = match ($params['_type']) {
            'skin' => $this->getSkinBaseDir($params),
            'locale' => $this->getLocaleBaseDir($params),
            default => $this->getBaseDir($params),
        };
        return $dir . DS . $file;
    }

    /**
     * Check for files existence by specified scheme
     *
     * If fallback enabled, the first found file will be returned. Otherwise the base package / default theme file,
     *   regardless of found or not.
     * If disabled, the lookup won't be performed to spare filesystem calls.
     *
     * @param string $file
     * @return string
     */
    protected function _fallback($file, array &$params, array $fallbackScheme = [[]])
    {
        if ($this->_shouldFallback) {
            foreach ($fallbackScheme as $try) {
                $params = array_merge($params, $try);
                $filename = $this->validateFile($file, $params);
                if ($filename) {
                    return $filename;
                }
            }
            $params['_package'] = self::BASE_PACKAGE;
            $params['_theme']   = self::DEFAULT_THEME;
        }
        return $this->validateFile($file, $params);
    }

    /**
     * Use this one to get existing file name with fallback to default
     *
     * $params['_type'] is required
     *
     * @param string $file
     * @return string
     * @throws Exception
     */
    public function getFilename($file, array $params)
    {
        Varien_Profiler::start(__METHOD__);

        // Prevent reading files outside of the proper directory while still allowing symlinked files
        if (str_contains($file, '..')) {
            Mage::log(sprintf('Invalid path requested: %s (params: %s)', $file, json_encode($params)), Zend_Log::ERR);
            throw new Exception('Invalid path requested.');
        }

        $this->updateParamDefaults($params);
        $result = $this->_fallback(
            $file,
            $params,
            $this->_fallback->getFallbackScheme(
                $params['_area'],
                $params['_package'],
                $params['_theme'],
            ),
        );
        Varien_Profiler::stop(__METHOD__);
        return $result;
    }

    /**
     * @param string $file
     * @return string
     */
    public function getLayoutFilename($file, array $params = [])
    {
        $params['_type'] = 'layout';
        return $this->getFilename($file, $params);
    }

    /**
     * @param string $file
     * @return string
     */
    public function getTemplateFilename($file, array $params = [])
    {
        $params['_type'] = 'template';
        return $this->getFilename($file, $params);
    }

    /**
     * @param string $file
     * @return string
     */
    public function getLocaleFileName($file, array $params = [])
    {
        $params['_type'] = 'locale';
        return $this->getFilename($file, $params);
    }

    /**
     * Get skin file url
     *
     * @param string|null $file
     * @return string
     * @throws Exception
     */
    public function getSkinUrl($file = null, array $params = [])
    {
        Varien_Profiler::start(__METHOD__);

        // Prevent reading files outside of the proper directory while still allowing symlinked files
        if (str_contains((string) $file, '..')) {
            Mage::log(sprintf('Invalid path requested: %s (params: %s)', $file, json_encode($params)), Zend_Log::ERR);
            throw new Exception('Invalid path requested.');
        }

        if (empty($params['_type'])) {
            $params['_type'] = 'skin';
        }
        if (empty($params['_default'])) {
            $params['_default'] = false;
        }
        $this->updateParamDefaults($params);
        if (!empty($file)) {
            // This updates $params with the base package and default theme if the file is not found
            $this->_fallback(
                $file,
                $params,
                $this->_fallback->getFallbackScheme(
                    $params['_area'],
                    $params['_package'],
                    $params['_theme'],
                ),
            );
        }
        $result = $this->getSkinBaseUrl($params) . (empty($file) ? '' : $file);

        Varien_Profiler::stop(__METHOD__);
        return $result;
    }

    /**
     * Design packages list getter
     * @return array
     */
    public function getPackageList()
    {
        $directory = Mage::getBaseDir('design') . DS . 'frontend';
        return Maho::listDirectories($directory);
    }

    /**
     * Design package (optional) themes list getter
     * @param string $package
     * @return array
     */
    public function getThemeList($package = null)
    {
        $result = [];

        if (is_null($package)) {
            foreach ($this->getPackageList() as $package) {
                $result[$package] = $this->getThemeList($package);
            }
        } else {
            $directory = Mage::getBaseDir('design') . DS . 'frontend' . DS . $package;
            $result = Maho::listDirectories($directory);
        }

        return $result;
    }

    /**
     * Get regex rules from config and check user-agent against them
     *
     * Rules must be stored in config as a serialized array(['regexp']=>'...', ['value'] => '...')
     * Will return false or found string.
     *
     * @param string $regexpsConfigPath
     * @return false|string
     */
    protected function _checkUserAgentAgainstRegexps($regexpsConfigPath)
    {
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            return false;
        }

        if (!empty(self::$_customThemeTypeCache[$regexpsConfigPath])) {
            return self::$_customThemeTypeCache[$regexpsConfigPath];
        }

        $configValueSerialized = Mage::getStoreConfig($regexpsConfigPath, $this->getStore());

        if (!$configValueSerialized) {
            return false;
        }

        try {
            $regexps = Mage::helper('core/unserializeArray')->unserialize($configValueSerialized);
        } catch (Exception $e) {
            Mage::logException($e);
        }

        if (empty($regexps)) {
            return false;
        }

        return self::getPackageByUserAgent($regexps, $regexpsConfigPath);
    }

    /**
     * Return package name based on design exception rules
     *
     * @param array $rules - design exception rules
     * @param string $regexpsConfigPath
     * @return bool|string
     */
    public static function getPackageByUserAgent(array $rules, $regexpsConfigPath = 'path_mock')
    {
        foreach ($rules as $rule) {
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
            if (!empty(self::$_regexMatchCache[$rule['regexp']][$userAgent])) {
                self::$_customThemeTypeCache[$regexpsConfigPath] = $rule['value'];
                return $rule['value'];
            }

            $regexp = '/' . trim($rule['regexp'], '/') . '/';

            if (@preg_match($regexp, $userAgent)) {
                self::$_regexMatchCache[$rule['regexp']][$userAgent] = true;
                self::$_customThemeTypeCache[$regexpsConfigPath] = $rule['value'];
                return $rule['value'];
            }
        }

        return false;
    }

    /**
     * Set file dir for css file
     *
     * @param string $file
     */
    protected function _setCallbackFileDir($file)
    {
        $file = str_replace(Mage::getBaseDir() . DS, '', $file);
        $this->_callbackFileDir = dirname($file);
    }

    /**
     * Prepare url for css replacement
     *
     * @param string $uri
     * @return string
     */
    protected function _prepareUrl($uri)
    {
        // check absolute or relative url
        if (!preg_match('/^https?:/i', $uri) && !preg_match('/^\//i', $uri)) {
            $fileDir = '';
            $pathParts = explode(DS, $uri);
            $fileDirParts = explode(DS, $this->_callbackFileDir);
            $store = $this->getStore();
            if (is_int($store)) {
                $store = Mage::app()->getStore($store);
            }
            if ($store->isAdmin()) {
                $secure = $store->isAdminUrlSecure();
            } else {
                $secure = $store->isFrontUrlSecure() && Mage::app()->getRequest()->isSecure();
            }

            if ($fileDirParts[0] == 'skin') {
                $baseUrl = Mage::getBaseUrl('skin', $secure);
                $fileDirParts = array_slice($fileDirParts, 1);
            } elseif ($fileDirParts[0] == 'media') {
                $baseUrl = Mage::getBaseUrl('media', $secure);
                $fileDirParts = array_slice($fileDirParts, 1);
            } else {
                $baseUrl = Mage::getBaseUrl('web', $secure);
            }

            foreach ($pathParts as $key => $part) {
                if ($part == '.' || $part == '..') {
                    unset($pathParts[$key]);
                }
                if ($part == '..' && count($fileDirParts)) {
                    $fileDirParts = array_slice($fileDirParts, 0, count($fileDirParts) - 1);
                }
            }

            if (count($fileDirParts)) {
                $fileDir = implode('/', $fileDirParts) . '/';
            }

            $uri = $baseUrl . $fileDir . implode('/', $pathParts);
        }
        return $uri;
    }
}
