<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2021-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Catalog_Product_Attribute_Set_Main_Formset extends Mage_Adminhtml_Block_Widget_Form
{
    #[\Override]
    protected function _prepareForm()
    {
        $data = Mage::getModel('eav/entity_attribute_set')
            ->load($this->getRequest()->getParam('id'));

        $form = new Varien_Data_Form();
        $fieldset = $form->addFieldset('set_name', ['legend' => Mage::helper('catalog')->__('Edit Set Name')]);
        $fieldset->addField('attribute_set_name', 'text', [
            'label' => Mage::helper('catalog')->__('Name'),
            'note' => Mage::helper('catalog')->__('For internal use.'),
            'name' => 'attribute_set_name',
            'required' => true,
            'class' => 'required-entry validate-no-html-tags',
            'value' => $data->getAttributeSetName(),
        ]);

        if (!$this->getRequest()->getParam('id', false)) {
            $fieldset->addField('gotoEdit', 'hidden', [
                'name' => 'gotoEdit',
                'value' => '1',
            ]);

            $sets = Mage::getModel('eav/entity_attribute_set')
                ->getResourceCollection()
                ->setEntityTypeFilter(Mage::registry('entityType'))
                ->setOrder('attribute_set_name', 'asc')
                ->load()
                ->toOptionArray();

            $fieldset->addField('skeleton_set', 'select', [
                'label' => Mage::helper('catalog')->__('Based On'),
                'name' => 'skeleton_set',
                'required' => true,
                'class' => 'required-entry',
                'values' => $sets,
            ]);
        }

        $form->setMethod('post');
        $form->setUseContainer(true);
        $form->setId('set_prop_form');
        $form->setAction($this->getUrl('*/*/save'));
        $form->setOnsubmit('return false;');
        $this->setForm($form);
        return $this;
    }

    #[\Override]
    protected function _initFormValues()
    {
        if ($this->getIsReadOnly()) {
            $fieldset = $this->getForm()->getElement('set_name');
            foreach ($fieldset->getElements() as $element) {
                $element->setDisabled(true);
            }
        }
        return $this;
    }
}
