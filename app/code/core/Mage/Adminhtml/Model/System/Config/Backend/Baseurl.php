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

class Mage_Adminhtml_Model_System_Config_Backend_Baseurl extends Mage_Core_Model_Config_Data
{
    /**
     * @return $this
     * @throws Mage_Core_Exception
     */
    #[\Override]
    protected function _beforeSave()
    {
        $value = str_replace(' ', '', $this->getValue());

        if ($value === '') {
            $label = $this->getFieldConfig()->descend('label');
            Mage::throwException(Mage::helper('core')->__('"%s" is a required value.', $label));
        }

        if (!preg_match('#^{{((un)?secure_)?base_url}}#', $value)) {
            $value = Mage::helper('core/url')->encodePunycode($value);
            $parsedUrl = parse_url($value);
            if (!isset($parsedUrl['scheme']) || !isset($parsedUrl['host'])) {
                Mage::throwException(Mage::helper('core')->__('The %s you entered is invalid. Please make sure that it follows "http://domain.com/" format.', $this->getFieldConfig()->label));
            } elseif (($parsedUrl['scheme'] != 'https') && ($parsedUrl['scheme'] != 'http')) {
                Mage::throwException(Mage::helper('core')->__('Invalid URL scheme.'));
            }
        }

        $value = rtrim($value, '/');
        /**
         * If value is special ({{}}) we don't need add slash
         */
        if (!preg_match('#}}$#', $value)) {
            $value .= '/';
        }

        $this->setValue($value);
        return $this;
    }

    #[\Override]
    protected function _afterLoad()
    {
        $value = $this->getValue();
        if (!preg_match('#^{{((un)?secure_)?base_url}}#', $value)) {
            $value = Mage::helper('core/url')->decodePunycode($value);
        }
        $this->setValue($value);
        return parent::_afterLoad();
    }
}
