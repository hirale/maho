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

class Mage_Core_Model_Email_Template_Filter extends Varien_Filter_Template
{
    /**
     * Use absolute links flag
     *
     * @var bool
     */
    protected $_useAbsoluteLinks = false;

    /**
     * Whether to allow SID in store directive: NO
     *
     * @var bool
     */
    protected $_useSessionInUrl = false;

    /**
     * @deprecated after 1.4.0.0-alpha2
     * @var Mage_Core_Model_Url
     */
    protected static $_urlInstance;

    /**
     * Modifier Callbacks
     *
     * @var array
     */
    protected $_modifiers = ['nl2br'  => ''];

    protected $_storeId = null;

    protected $_plainTemplateMode = false;

    /**
     * @var bool|string
     */
    protected $_inlineCssFile = false;

    /** @var Mage_Admin_Model_Variable  */
    protected $_permissionVariable;

    /** @var Mage_Admin_Model_Block  */
    protected $_permissionBlock;

    /**
     * Setup callbacks for filters
     *
     */
    public function __construct()
    {
        $this->_modifiers['escape'] = [$this, 'modifierEscape'];
        $this->_permissionVariable = Mage::getModel('admin/variable');
        $this->_permissionBlock = Mage::getModel('admin/block');
    }

    /**
     * Set use absolute links flag
     *
     * @param bool $flag
     * @return $this
     */
    public function setUseAbsoluteLinks($flag)
    {
        $this->_useAbsoluteLinks = $flag;
        return $this;
    }

    /**
     * Setter whether SID is allowed in store directive
     * Doesn't set anything intentionally, since SID is not allowed in any kind of emails
     *
     * @param bool $flag
     * @return $this
     */
    public function setUseSessionInUrl($flag)
    {
        $this->_useSessionInUrl = $flag;
        return $this;
    }

    /**
     * Setter
     *
     * @param bool $plainTemplateMode
     * @return $this
     */
    public function setPlainTemplateMode($plainTemplateMode)
    {
        $this->_plainTemplateMode = (bool) $plainTemplateMode;
        return $this;
    }

    /**
     * Getter
     *
     * @return bool
     */
    public function getPlainTemplateMode()
    {
        return $this->_plainTemplateMode;
    }

    /**
     * Setter
     *
     * @param Mage_Core_Model_Store|int $storeId
     * @return $this
     */
    public function setStoreId($storeId)
    {
        $this->_storeId = $storeId;
        return $this;
    }

    /**
     * Getter
     * if $_storeId is null return Design store id
     *
     * @return int
     * @throws Mage_Core_Model_Store_Exception
     */
    public function getStoreId()
    {
        if ($this->_storeId === null) {
            $this->_storeId = Mage::app()->getStore()->getId();
        }
        return $this->_storeId;
    }

    /**
     * Retrieve Block html directive
     *
     * @param array $construction
     * @return string
     */
    public function blockDirective($construction)
    {
        $skipParams = ['type', 'id', 'output'];
        $blockParameters = $this->_getIncludeParameters($construction[2]);
        $layout = Mage::app()->getLayout();
        $block = null;

        if (isset($blockParameters['type'])) {
            if ($this->_permissionBlock->isTypeAllowed($blockParameters['type'])) {
                $type = $blockParameters['type'];
                $block = $layout->createBlock($type, null, $blockParameters);
            } else {
                Mage::log('Security problem: ' . $blockParameters['type'] . ' has not been whitelisted.');
            }
        } elseif (isset($blockParameters['id'])) {
            $block = $layout->createBlock('cms/block');
            if ($block) {
                $block->setBlockId($blockParameters['id']);
            }
        }

        if ($block) {
            $block->setBlockParams($blockParameters);
            foreach ($blockParameters as $k => $v) {
                if (in_array($k, $skipParams)) {
                    continue;
                }
                $block->setDataUsingMethod($k, $v);
            }
        } else {
            return '';
        }

        if (isset($blockParameters['output'])) {
            $method = $blockParameters['output'];
        }
        if (!isset($method) || !is_string($method) || !method_exists($block, $method)) {
            $method = 'toHtml';
        }
        return $block->$method();
    }

    /**
     * Retrieve layout html directive
     *
     * @param array $construction
     * @return string
     * @throws Mage_Core_Exception
     */
    public function layoutDirective($construction)
    {
        $skipParams = ['handle', 'area'];

        $params = $this->_getIncludeParameters($construction[2]);
        $layout = Mage::getModel('core/layout');
        /** @var Mage_Core_Model_Layout $layout */
        if (isset($params['area'])) {
            $layout->setArea($params['area']);
        } else {
            $layout->setArea(Mage::app()->getLayout()->getArea());
        }

        $layout->getUpdate()->addHandle($params['handle']);
        $layout->getUpdate()->load();

        $layout->generateXml();
        $layout->generateBlocks();

        /** @var Mage_Core_Block_Abstract $block */
        foreach ($layout->getAllBlocks() as $blockName => $block) {
            foreach ($params as $k => $v) {
                if (in_array($k, $skipParams)) {
                    continue;
                }

                $block->setDataUsingMethod($k, $v);
            }
        }

        /**
         * Add output method for first block
         */
        $allBlocks = $layout->getAllBlocks();
        $firstBlock = reset($allBlocks);
        if ($firstBlock) {
            $layout->addOutputBlock($firstBlock->getNameInLayout());
        }

        $layout->setDirectOutput(false);
        return $layout->getOutput();
    }

    /**
     * Retrieve block parameters
     *
     * @param mixed $value
     * @return array
     */
    protected function _getBlockParameters($value)
    {
        $tokenizer = new Varien_Filter_Template_Tokenizer_Parameter();
        $tokenizer->setString($value);

        return $tokenizer->tokenize();
    }

    /**
     * Retrieve Skin URL directive
     *
     * @param array $construction
     * @return string
     * @throws Exception
     */
    public function skinDirective($construction)
    {
        $params = $this->_getIncludeParameters($construction[2]);
        $params['_absolute'] = $this->_useAbsoluteLinks;

        return Mage::getDesign()->getSkinUrl($params['url'], $params);
    }

    /**
     * Retrieve media file URL directive
     *
     * @param array $construction
     * @return string
     */
    public function mediaDirective($construction)
    {
        $params = $this->_getIncludeParameters($construction[2]);
        return Mage::getBaseUrl('media') . $params['url'];
    }

    /**
     * Retrieve store URL directive
     * Support url and direct_url properties
     *
     * @param array $construction
     * @return string
     * @throws Mage_Core_Model_Store_Exception
     */
    public function storeDirective($construction)
    {
        $params = $this->_getIncludeParameters($construction[2]);
        if (!isset($params['_query'])) {
            $params['_query'] = [];
        }
        foreach ($params as $k => $v) {
            if (str_starts_with($k, '_query_')) {
                $params['_query'][substr($k, 7)] = $v;
                unset($params[$k]);
            }
        }
        $params['_absolute'] = $this->_useAbsoluteLinks;

        if ($this->_useSessionInUrl === false) {
            $params['_nosid'] = true;
        }

        if (isset($params['direct_url'])) {
            $path = '';
            $params['_direct'] = $params['direct_url'];
            unset($params['direct_url']);
        } else {
            $path = $params['url'] ?? '';
            unset($params['url']);
        }

        return Mage::app()->getStore(Mage::getDesign()->getStore())->getUrl($path, $params);
    }

    /**
     * Directive for converting special characters to HTML entities
     * Supported options:
     *     allowed_tags - Comma separated html tags that have not to be converted
     *
     * @param array $construction
     * @return string
     */
    public function htmlescapeDirective($construction)
    {
        $params = $this->_getIncludeParameters($construction[2]);
        if (!isset($params['var'])) {
            return '';
        }

        $allowedTags = null;
        if (isset($params['allowed_tags'])) {
            $allowedTags = preg_split('/\s*\,\s*/', $params['allowed_tags'], 0, PREG_SPLIT_NO_EMPTY);
        }

        return Mage::helper('core')->escapeHtml($params['var'], $allowedTags);
    }

    /**
     * Var directive with modifiers support
     *
     * @param array $construction
     * @return string
     * @throws Mage_Core_Exception
     */
    #[\Override]
    public function varDirective($construction)
    {
        if (count($this->_templateVars) == 0) {
            // If template preprocessing
            return $construction[0];
        }

        $parts = explode('|', $construction[2], 2);
        if (count($parts) === 2) {
            [$variableName, $modifiersString] = $parts;
            return $this->_amplifyModifiers($this->_getVariable($variableName, ''), $modifiersString);
        }
        return $this->_getVariable($construction[2], '');
    }

    /**
     * Apply modifiers one by one, with specified params
     *
     * Modifier syntax: modifier1[:param1:param2:...][|modifier2:...]
     *
     * @param string $value
     * @param string $modifiers
     * @return string
     */
    protected function _amplifyModifiers($value, $modifiers)
    {
        foreach (explode('|', $modifiers) as $part) {
            if (empty($part)) {
                continue;
            }
            $params   = explode(':', $part);
            $modifier = array_shift($params);
            if (isset($this->_modifiers[$modifier])) {
                $callback = $this->_modifiers[$modifier];
                if (!$callback) {
                    $callback = $modifier;
                }
                array_unshift($params, $value);
                $value = call_user_func_array($callback, $params);
            }
        }
        return $value;
    }

    /**
     * Escape specified string
     *
     * @param string $value
     * @param string $type
     * @return string
     */
    public function modifierEscape($value, $type = 'html')
    {
        return match ($type) {
            'html' => htmlspecialchars($value, ENT_QUOTES),
            'htmlentities' => htmlentities($value, ENT_QUOTES),
            'url' => rawurlencode($value),
            default => $value,
        };
    }

    /**
     * HTTP Protocol directive
     *
     * Using:
     * {{protocol}} - current protocol http or https
     * {{protocol url="www.domain.com/"}} domain URL with current protocol
     * {{protocol http="http://url" https="https://url"}
     * also allow additional parameter "store"
     *
     * @param array $construction
     * @return string
     * @throws Mage_Core_Model_Store_Exception
     */
    public function protocolDirective($construction)
    {
        $params = $this->_getIncludeParameters($construction[2]);
        $store = null;
        if (isset($params['store'])) {
            $store = Mage::app()->getSafeStore($params['store']);
        }
        $isSecure = Mage::app()->isCurrentlySecure();
        $protocol = $isSecure ? 'https' : 'http';
        if (isset($params['url'])) {
            return $protocol . '://' . $params['url'];
        } elseif (isset($params['http']) && isset($params['https'])) {
            if ($isSecure) {
                return $params['https'];
            }
            return $params['http'];
        }

        return $protocol;
    }

    /**
     * Store config directive
     *
     * @param array $construction
     * @return string
     * @throws Mage_Core_Model_Store_Exception
     */
    public function configDirective($construction)
    {
        $configValue = '';
        $params = $this->_getIncludeParameters($construction[2]);
        $storeId = $this->getStoreId();
        if (isset($params['path']) && $this->_permissionVariable->isPathAllowed($params['path'])) {
            $configValue = Mage::getStoreConfig($params['path'], $storeId);
        }
        return $configValue;
    }

    /**
     * Custom Variable directive
     *
     * @param array $construction
     * @return string
     * @throws Mage_Core_Model_Store_Exception
     */
    public function customvarDirective($construction)
    {
        $customVarValue = '';
        $params = $this->_getIncludeParameters($construction[2]);
        if (isset($params['code'])) {
            $variable = Mage::getModel('core/variable')
                ->setStoreId($this->getStoreId())
                ->loadByCode($params['code']);
            $mode = $this->getPlainTemplateMode()
                ? Mage_Core_Model_Variable::TYPE_TEXT
                : Mage_Core_Model_Variable::TYPE_HTML;
            if ($value = $variable->getValue($mode)) {
                $customVarValue = $value;
            }
        }
        return $customVarValue;
    }

    /**
     * This directive will allow CSS files to be applied inline to the HTML in the email template.
     * Syntax: {{inlinecss file=""}}  If this directive is used, the file will be stored on this object so that
     * it can be retrieved later
     *
     * @param array $construction
     * @return string
     */
    public function inlinecssDirective($construction)
    {
        $params = $this->_getIncludeParameters($construction[2]);
        if (isset($params['file'])) {
            $this->_setInlineCssFile($params['file']);
        }
        return '';
    }

    /**
     * Set filename of CSS file to inline
     *
     * @param string $filename
     * @return $this
     */
    protected function _setInlineCssFile($filename)
    {
        $this->_inlineCssFile = $filename;
        return $this;
    }

    /**
     * Get filename of CSS file to inline
     *
     * @return bool|string
     */
    public function getInlineCssFile()
    {
        return $this->_inlineCssFile;
    }

    /**
     * Filter the string as template.
     * Rewritten for logging exceptions
     *
     * @param string $value
     * @return string
     */
    #[\Override]
    public function filter($value)
    {
        try {
            $value = parent::filter($value);
        } catch (Exception $e) {
            $value = '';
            Mage::logException($e);
        }
        return $value;
    }

    /**
     * Return variable value for var construction
     *
     * @param string $value raw parameters
     * @param string $default default value
     * @return string
     * @throws Mage_Core_Exception
     */
    #[\Override]
    protected function _getVariable($value, $default = '{no_value_defined}')
    {
        Mage::register('varProcessing', true);
        try {
            $result = parent::_getVariable($value, $default);
        } catch (Exception $e) {
            $result = '';
            Mage::logException($e);
        }
        Mage::unregister('varProcessing');
        return $result;
    }
}
