<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Media library js helper
 *
 * @package    Mage_Adminhtml
 * @deprecated since 1.7.0.0
 */
class Mage_Adminhtml_Helper_Media_Js extends Mage_Core_Helper_Js
{
    protected $_moduleName = 'Mage_Adminhtml';

    public function __construct()
    {
        $this->_translateData = [
            'Complete' => $this->__('Complete'),
            'File size should be more than 0 bytes' => $this->__('File size should be more than 0 bytes'),
            'Upload Security Error' => $this->__('Upload Security Error'),
            'Upload HTTP Error'     => $this->__('Upload HTTP Error'),
            'Upload I/O Error'     => $this->__('Upload I/O Error'),
            'SSL Error: Invalid or self-signed certificate'     => $this->__('SSL Error: Invalid or self-signed certificate'),
            'Tb' => $this->__('Tb'),
            'Gb' => $this->__('Gb'),
            'Mb' => $this->__('Mb'),
            'Kb' => $this->__('Kb'),
            'b' => $this->__('b'),
        ];
    }

    /**
     * Retrieve JS translator initialization javascript
     *
     * @return string
     */
    #[\Override]
    public function getTranslatorScript()
    {
        $script = 'if (typeof(Translator) == \'undefined\') {'
                . '    var Translator = new Translate(' . $this->getTranslateJson() . ');'
                . '} else {'
                . '    Translator.add(' . $this->getTranslateJson() . ');'
                . '}';
        return $this->getScript($script);
    }
}
