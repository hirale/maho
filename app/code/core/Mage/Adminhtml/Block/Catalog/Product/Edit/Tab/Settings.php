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

class Mage_Adminhtml_Block_Catalog_Product_Edit_Tab_Settings extends Mage_Adminhtml_Block_Widget_Form
{
    #[\Override]
    protected function _prepareLayout()
    {
        $this->setChild(
            'continue_button',
            $this->getLayout()->createBlock('adminhtml/widget_button')
                ->setData([
                    'label'     => Mage::helper('catalog')->__('Continue'),
                    'onclick'   => "setSettings('" . $this->getContinueUrl() . "','attribute_set_id','product_type')",
                    'class'     => 'save',
                ]),
        );
        return parent::_prepareLayout();
    }

    #[\Override]
    protected function _prepareForm()
    {
        $form = new Varien_Data_Form();
        $fieldset = $form->addFieldset('settings', ['legend' => Mage::helper('catalog')->__('Create Product Settings')]);

        $entityType = Mage::registry('product')->getResource()->getEntityType();

        $fieldset->addField('attribute_set_id', 'select', [
            'label' => Mage::helper('catalog')->__('Attribute Set'),
            'title' => Mage::helper('catalog')->__('Attribute Set'),
            'name'  => 'set',
            'value' => $entityType->getDefaultAttributeSetId(),
            'values' => Mage::getResourceModel('eav/entity_attribute_set_collection')
                ->setEntityTypeFilter($entityType->getId())
                ->setOrder('attribute_set_name', 'asc')
                ->load()
                ->toOptionArray(),
        ]);

        $fieldset->addField('product_type', 'select', [
            'label' => Mage::helper('catalog')->__('Product Type'),
            'title' => Mage::helper('catalog')->__('Product Type'),
            'name'  => 'type',
            'value' => '',
            'values' => Mage::getModel('catalog/product_type')->getOptionArray(),
        ]);

        $fieldset->addField('continue_button', 'note', [
            'text' => $this->getChildHtml('continue_button'),
        ]);

        $this->setForm($form);
        return $this;
    }

    public function getContinueUrl()
    {
        return $this->getUrl('*/*/new', [
            '_current'  => true,
            'set'       => '{{attribute_set}}',
            'type'      => '{{type}}',
        ]);
    }
}
