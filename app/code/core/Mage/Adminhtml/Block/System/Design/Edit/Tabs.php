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

class Mage_Adminhtml_Block_System_Design_Edit_Tabs extends Mage_Adminhtml_Block_Widget_Tabs
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('design_tabs');
        $this->setDestElementId('design_edit_form');
        $this->setTitle(Mage::helper('core')->__('Design Change'));
    }

    #[\Override]
    protected function _prepareLayout()
    {
        $this->addTab('general', [
            'label'     => Mage::helper('core')->__('General'),
            'content'   => $this->getLayout()->createBlock('adminhtml/system_design_edit_tab_general')->toHtml(),
        ]);

        return parent::_prepareLayout();
    }
}
