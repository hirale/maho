<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2021-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Catalog_Product_Edit_Action_Attribute extends Mage_Adminhtml_Block_Widget
{
    #[\Override]
    protected function _prepareLayout()
    {
        $this->setChild(
            'back_button',
            $this->getLayout()->createBlock('adminhtml/widget_button')
                ->setData([
                    'label'     => Mage::helper('catalog')->__('Back'),
                    'onclick'   => Mage::helper('core/js')->getSetLocationJs(
                        $this->getUrl(
                            '*/catalog_product/',
                            ['store' => $this->getRequest()->getParam('store', 0)],
                        ),
                    ),
                    'class' => 'back',
                ]),
        );

        $this->setChild(
            'reset_button',
            $this->getLayout()->createBlock('adminhtml/widget_button')
                ->setData([
                    'label'     => Mage::helper('catalog')->__('Reset'),
                    'onclick'   => Mage::helper('core/js')->getSetLocationJs($this->getUrl('*/*/*', ['_current' => true])),
                ]),
        );

        $this->setChild(
            'save_button',
            $this->getLayout()->createBlock('adminhtml/widget_button')
                ->setData([
                    'label'     => Mage::helper('catalog')->__('Save'),
                    'onclick'   => 'attributesForm.submit()',
                    'class'     => 'save',
                ]),
        );
        return $this;
    }

    /**
     * Retrieve selected products for update
     *
     * @return Mage_Catalog_Model_Resource_Product_Collection
     */
    public function getProducts()
    {
        return $this->_getHelper()->getProducts();
    }

    /**
     * Retrieve block attributes update helper
     *
     * @return Mage_Adminhtml_Helper_Catalog_Product_Edit_Action_Attribute
     */
    protected function _getHelper()
    {
        return $this->helper('adminhtml/catalog_product_edit_action_attribute');
    }

    /**
     * Retrieve back button html code
     *
     * @return string
     */
    public function getBackButtonHtml()
    {
        return $this->getChildHtml('back_button');
    }

    /**
     * Retrieve cancel button html code
     *
     * @return string
     */
    public function getCancelButtonHtml()
    {
        return $this->getChildHtml('reset_button');
    }

    /**
     * Retrieve save button html code
     *
     * @return string
     */
    public function getSaveButtonHtml()
    {
        return $this->getChildHtml('save_button');
    }

    /**
     * Get save url
     *
     * @return string
     */
    public function getSaveUrl()
    {
        return $this->getUrl('*/*/save', ['store' => Mage::helper('adminhtml/catalog_product_edit_action_attribute')->getSelectedStoreId()]);
    }

    /**
     * Get validation url
     *
     * @return string
     */
    public function getValidationUrl()
    {
        return $this->getUrl('*/*/validate', ['_current' => true]);
    }
}
