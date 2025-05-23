<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Model_System_Config_Backend_Locale extends Mage_Core_Model_Config_Data
{
    /**
     * Validate data before save data
     *
     * @return Mage_Core_Model_Abstract
     * @throws Mage_Core_Exception
     */
    #[\Override]
    protected function _beforeSave()
    {
        $allCurrenciesOptions = Mage::getSingleton('adminhtml/system_config_source_locale_currency_all')
            ->toOptionArray(true);

        $allCurrenciesValues = array_column($allCurrenciesOptions, 'value');

        foreach ($this->getValue() as $currency) {
            if (!in_array($currency, $allCurrenciesValues)) {
                Mage::throwException(Mage::helper('adminhtml')->__('Currency doesn\'t exist.'));
            }
        }

        return parent::_beforeSave();
    }

    /**
     * @return $this
     */
    #[\Override]
    protected function _afterSave()
    {
        $collection = Mage::getModel('core/config_data')
            ->getCollection()
            ->addPathFilter('currency/options');

        $values     = explode(',', $this->getValue());
        $exceptions = [];

        foreach ($collection as $data) {
            $match = false;
            $scopeName = Mage::helper('adminhtml')->__('Default scope');

            if (preg_match('/(base|default)$/', $data->getPath(), $match)) {
                if (!in_array($data->getValue(), $values)) {
                    $currencyName = Mage::app()->getLocale()->currency($data->getValue())->getName();
                    if ($match[1] == 'base') {
                        $fieldName = Mage::helper('adminhtml')->__('Base currency');
                    } else {
                        $fieldName = Mage::helper('adminhtml')->__('Display default currency');
                    }

                    switch ($data->getScope()) {
                        case 'default':
                            $scopeName = Mage::helper('adminhtml')->__('Default scope');
                            break;

                        case 'website':
                            $websiteName = Mage::getModel('core/website')->load($data->getScopeId())->getName();
                            $scopeName = Mage::helper('adminhtml')->__('website(%s) scope', $websiteName);
                            break;

                        case 'store':
                            $storeName = Mage::getModel('core/store')->load($data->getScopeId())->getName();
                            $scopeName = Mage::helper('adminhtml')->__('store(%s) scope', $storeName);
                            break;
                    }

                    $exceptions[] = Mage::helper('adminhtml')->__('Currency "%s" is used as %s in %s.', $currencyName, $fieldName, $scopeName);
                }
            }
        }
        if ($exceptions) {
            Mage::throwException(implode("\n", $exceptions));
        }

        return $this;
    }
}
