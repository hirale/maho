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

class Mage_Adminhtml_Block_Sales_Order_View_Tab_Invoices extends Mage_Adminhtml_Block_Widget_Grid implements Mage_Adminhtml_Block_Widget_Tab_Interface
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('order_invoices');
        $this->setUseAjax(true);
    }

    /**
     * Retrieve collection class
     *
     * @return string
     */
    protected function _getCollectionClass()
    {
        return 'sales/order_invoice_grid_collection';
    }

    #[\Override]
    protected function _prepareCollection()
    {
        $collection = Mage::getResourceModel($this->_getCollectionClass())
            ->addFieldToSelect('entity_id')
            ->addFieldToSelect('created_at')
            ->addFieldToSelect('order_id')
            ->addFieldToSelect('increment_id')
            ->addFieldToSelect('state')
            ->addFieldToSelect('grand_total')
            ->addFieldToSelect('base_grand_total')
            ->addFieldToSelect('store_currency_code')
            ->addFieldToSelect('base_currency_code')
            ->addFieldToSelect('order_currency_code')
            ->addFieldToSelect('billing_name')
            ->setOrderFilter($this->getOrder())
        ;
        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('increment_id', [
            'header'    => Mage::helper('sales')->__('Invoice #'),
            'index'     => 'increment_id',
            'width'     => '120px',
        ]);

        $this->addColumn('billing_name', [
            'header' => Mage::helper('sales')->__('Bill to Name'),
            'index' => 'billing_name',
        ]);

        $this->addColumn('created_at', [
            'header'    => Mage::helper('sales')->__('Invoice Date'),
            'index'     => 'created_at',
            'type'      => 'datetime',
        ]);

        $this->addColumn('state', [
            'header'    => Mage::helper('sales')->__('Status'),
            'index'     => 'state',
            'type'      => 'options',
            'options'   => Mage::getModel('sales/order_invoice')->getStates(),
        ]);

        $this->addColumn('base_grand_total', [
            'header'    => Mage::helper('customer')->__('Amount'),
            'index'     => 'base_grand_total',
            'type'      => 'currency',
            'currency'  => 'base_currency_code',
        ]);

        return parent::_prepareColumns();
    }

    /**
     * Retrieve order model instance
     *
     * @return Mage_Sales_Model_Order
     */
    public function getOrder()
    {
        return Mage::registry('current_order');
    }

    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl(
            '*/sales_order_invoice/view',
            [
                'invoice_id' => $row->getId(),
                'order_id'  => $row->getOrderId(),
            ],
        );
    }

    #[\Override]
    public function getGridUrl()
    {
        return $this->getUrl('*/*/invoices', ['_current' => true]);
    }

    #[\Override]
    public function getTabLabel()
    {
        return Mage::helper('sales')->__('Invoices');
    }

    #[\Override]
    public function getTabTitle()
    {
        return Mage::helper('sales')->__('Invoices');
    }

    #[\Override]
    public function canShowTab()
    {
        return Mage::getSingleton('admin/session')->isAllowed('sales/invoice');
    }

    #[\Override]
    public function isHidden()
    {
        return false;
    }
}
