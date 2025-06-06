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

class Mage_Adminhtml_Block_Catalog_Product_Edit_Action_Attribute_Tab_Attributes extends Mage_Adminhtml_Block_Catalog_Form implements Mage_Adminhtml_Block_Widget_Tab_Interface
{
    #[\Override]
    protected function _construct()
    {
        parent::_construct();
        $this->setShowGlobalIcon(true);
    }

    /**
     * @return $this
     */
    #[\Override]
    protected function _prepareForm()
    {
        $this->setFormExcludedFieldList([
            'tier_price','gallery', 'media_gallery', 'recurring_profile', 'group_price',
        ]);
        Mage::dispatchEvent('adminhtml_catalog_product_form_prepare_excluded_field_list', ['object' => $this]);

        $form = new Varien_Data_Form();
        $fieldset = $form->addFieldset('fields', ['legend' => Mage::helper('catalog')->__('Attributes')]);
        $attributes = $this->getAttributes();
        /**
         * Initialize product object as form property
         * for using it in elements generation
         */
        $form->setDataObject(Mage::getModel('catalog/product'));
        $this->_setFieldset($attributes, $fieldset, $this->getFormExcludedFieldList());
        $form->setFieldNameSuffix('attributes');
        $this->setForm($form);
        return $this;
    }

    /**
     * Retrieve attributes for product massupdate
     *
     * @return array
     */
    public function getAttributes()
    {
        /** @var Mage_Adminhtml_Helper_Catalog_Product_Edit_Action_Attribute $helper */
        $helper = $this->helper('adminhtml/catalog_product_edit_action_attribute');
        return $helper->getAttributes()->getItems();
    }

    /**
     * Additional element types for product attributes
     *
     * @return array
     */
    #[\Override]
    protected function _getAdditionalElementTypes()
    {
        return [
            'price' => Mage::getConfig()->getBlockClassName('adminhtml/catalog_product_helper_form_price'),
            'weight' => Mage::getConfig()->getBlockClassName('adminhtml/catalog_product_helper_form_weight'),
            'image' => Mage::getConfig()->getBlockClassName('adminhtml/catalog_product_helper_form_image'),
            'boolean' => Mage::getConfig()->getBlockClassName('adminhtml/catalog_product_helper_form_boolean'),
        ];
    }

    /**
     * Custom additional element html
     *
     * @param Varien_Data_Form_Element_Abstract $element
     * @return string
     */
    #[\Override]
    protected function _getAdditionalElementHtml($element)
    {
        // Add name attribute to checkboxes that correspond to multiselect elements
        $nameAttributeHtml = ($element->getExtType() === 'multiple') ? 'name="' . $element->getId() . '_checkbox"'
            : '';
        return '<span class="attribute-change-checkbox"><input type="checkbox" id="' . $element->getId()
             . '-checkbox" ' . $nameAttributeHtml . ' onclick="toogleFieldEditMode(this, \'' . $element->getId()
             . '\')" /><label for="' . $element->getId() . '-checkbox">' . Mage::helper('catalog')->__('Change')
             . '</label></span>
                <script type="text/javascript">initDisableFields(\'' . $element->getId() . '\')</script>';
    }

    /**
     * @return string
     */
    #[\Override]
    public function getTabLabel()
    {
        return Mage::helper('catalog')->__('Attributes');
    }

    /**
     * @return string
     */
    #[\Override]
    public function getTabTitle()
    {
        return Mage::helper('catalog')->__('Attributes');
    }

    /**
     * @return true
     */
    #[\Override]
    public function canShowTab()
    {
        return true;
    }

    /**
     * @return false
     */
    #[\Override]
    public function isHidden()
    {
        return false;
    }
}
