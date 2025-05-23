<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Sales_Order_Create_Customer extends Mage_Adminhtml_Block_Sales_Order_Create_Abstract
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('sales_order_create_customer');
    }

    /**
     * @return string
     */
    public function getHeaderText()
    {
        return Mage::helper('sales')->__('Please Select a Customer');
    }

    /**
     * @return string
     */
    public function getButtonsHtml()
    {
        $html = '';

        $addButtonData = [
            'label'     => Mage::helper('sales')->__('Create New Customer'),
            'onclick'   => 'order.setCustomerId(false)',
            'class'     => 'add',
        ];
        $html .= $this->getLayout()->createBlock('adminhtml/widget_button')->setData($addButtonData)->toHtml();

        $addButtonData = [
            'label'     => Mage::helper('sales')->__('Create Guest Order'),
            'onclick'   => 'order.setCustomerIsGuest()',
            'class'     => 'add',
        ];
        $html .= $this->getLayout()->createBlock('adminhtml/widget_button')->setData($addButtonData)->toHtml();

        return $html;
    }
}
