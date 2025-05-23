<?php

/**
 * Maho
 *
 * @package    Mage_Widget
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Widget_Block_Adminhtml_Widget_Instance extends Mage_Adminhtml_Block_Widget_Grid_Container
{
    /**
     * Block constructor
     */
    public function __construct()
    {
        $this->_blockGroup = 'widget';
        $this->_controller = 'adminhtml_widget_instance';
        $this->_headerText = Mage::helper('widget')->__('Manage Widget Instances');
        parent::__construct();
        $this->_updateButton('add', 'label', Mage::helper('widget')->__('Add New Widget Instance'));
    }
}
