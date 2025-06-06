<?php

/**
 * Maho
 *
 * @package    Mage_CurrencySymbol
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_CurrencySymbol_Block_Adminhtml_System_Currencysymbol extends Mage_Adminhtml_Block_Widget_Form
{
    /**
     * Custom currency symbol properties
     *
     * @var array
     */
    protected $_symbolsData = [];

    /**
     * Prepares layout
     *
     * @return Mage_Core_Block_Abstract
     */
    #[\Override]
    protected function _prepareLayout()
    {
        return parent::_prepareLayout();
    }

    /**
     * Returns page header
     *
     * @return string
     */
    public function getHeader()
    {
        return Mage::helper('adminhtml')->__('Manage Currency Symbols');
    }

    /**
     * Returns 'Save Currency Symbol' button's HTML code
     *
     * @return string
     */
    public function getSaveButtonHtml()
    {
        /** @var Mage_Core_Block_Abstract $block */
        $block = $this->getLayout()->createBlock('adminhtml/widget_button');
        $block->setData([
            'label'     => Mage::helper('currencysymbol')->__('Save Currency Symbols'),
            'onclick'   => 'currencySymbolsForm.submit();',
            'class'     => 'save',
        ]);

        return $block->toHtml();
    }

    /**
     * Returns URL for save action
     *
     * @return string
     */
    public function getFormActionUrl()
    {
        return $this->getUrl('*/*/save');
    }

    /**
     * Returns website id
     *
     * @return int
     */
    public function getWebsiteId()
    {
        return $this->getRequest()->getParam('website');
    }

    /**
     * Returns store id
     *
     * @return int
     */
    public function getStoreId()
    {
        return $this->getRequest()->getParam('store');
    }

    /**
     * Returns Custom currency symbol properties
     *
     * @return array
     */
    public function getCurrencySymbolsData()
    {
        if (!$this->_symbolsData) {
            $this->_symbolsData =  Mage::getModel('currencysymbol/system_currencysymbol')
                ->getCurrencySymbolsData();
        }
        return $this->_symbolsData;
    }

    /**
     * Returns inheritance text
     *
     * @return string
     */
    public function getInheritText()
    {
        return Mage::helper('currencysymbol')->__('Use Standard');
    }
}
