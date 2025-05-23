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

class Mage_Adminhtml_Block_Report_Shopcart_Abandoned_Grid extends Mage_Adminhtml_Block_Report_Grid_Shopcart
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('gridAbandoned');
    }

    #[\Override]
    protected function _prepareCollection()
    {
        /** @var Mage_Reports_Model_Resource_Quote_Collection $collection */
        $collection = Mage::getResourceModel('reports/quote_collection');

        $filter = $this->getParam($this->getVarNameFilter(), []);
        if ($filter) {
            $filter = base64_decode($filter);
            parse_str(urldecode($filter), $data);
        }

        if (!empty($data)) {
            $collection->prepareForAbandonedReport($this->_storeIds, $data);
        } else {
            $collection->prepareForAbandonedReport($this->_storeIds);
        }

        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    #[\Override]
    protected function _addColumnFilterToCollection($column)
    {
        $field = $column->getFilterIndex() ?: $column->getIndex();
        $skip = ['subtotal', 'customer_name', 'email'/*, 'created_at', 'updated_at'*/];

        if (in_array($field, $skip)) {
            return $this;
        }

        parent::_addColumnFilterToCollection($column);
        return $this;
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('customer_name', [
            'header'    => Mage::helper('reports')->__('Customer Name'),
            'index'     => 'customer_name',
            'sortable'  => false,
        ]);

        $this->addColumn('email', [
            'header'    => Mage::helper('reports')->__('Email'),
            'index'     => 'email',
            'sortable'  => false,
        ]);

        $this->addColumn('items_count', [
            'header'    => Mage::helper('reports')->__('Number of Items'),
            'width'     => '80px',
            'index'     => 'items_count',
            'sortable'  => false,
            'type'      => 'number',
        ]);

        $this->addColumn('items_qty', [
            'header'    => Mage::helper('reports')->__('Quantity of Items'),
            'width'     => '80px',
            'index'     => 'items_qty',
            'sortable'  => false,
            'type'      => 'number',
        ]);

        if ($this->getRequest()->getParam('website')) {
            $storeIds = Mage::app()->getWebsite($this->getRequest()->getParam('website'))->getStoreIds();
        } elseif ($this->getRequest()->getParam('group')) {
            $storeIds = Mage::app()->getGroup($this->getRequest()->getParam('group'))->getStoreIds();
        } elseif ($this->getRequest()->getParam('store')) {
            $storeIds = [(int) $this->getRequest()->getParam('store')];
        } else {
            $storeIds = [];
        }
        $this->setStoreIds($storeIds);
        $currencyCode = $this->getCurrentCurrencyCode();

        $this->addColumn('subtotal', [
            'header'        => Mage::helper('reports')->__('Subtotal'),
            'width'         => '80px',
            'type'          => 'currency',
            'currency_code' => $currencyCode,
            'index'         => 'subtotal',
            'sortable'      => false,
            'renderer'      => 'adminhtml/report_grid_column_renderer_currency',
            'rate'          => $this->getRate($currencyCode),
        ]);

        $this->addColumn('coupon_code', [
            'header'    => Mage::helper('reports')->__('Applied Coupon'),
            'width'     => '80px',
            'index'     => 'coupon_code',
            'sortable'  => false,
        ]);

        $this->addColumn('created_at', [
            'header'    => Mage::helper('reports')->__('Created At'),
            'width'     => '170px',
            'type'      => 'datetime',
            'index'     => 'created_at',
            'filter_index' => 'main_table.created_at',
            'sortable'  => false,
        ]);

        $this->addColumn('updated_at', [
            'header'    => Mage::helper('reports')->__('Updated At'),
            'width'     => '170px',
            'type'      => 'datetime',
            'index'     => 'updated_at',
            'filter_index' => 'main_table.updated_at',
            'sortable'  => false,
        ]);

        $this->addColumn('remote_ip', [
            'header'    => Mage::helper('reports')->__('IP Address'),
            'width'     => '80px',
            'index'     => 'remote_ip',
            'sortable'  => false,
        ]);

        $this->addExportType('*/*/exportAbandonedCsv', Mage::helper('reports')->__('CSV'));
        $this->addExportType('*/*/exportAbandonedExcel', Mage::helper('reports')->__('Excel XML'));

        return parent::_prepareColumns();
    }

    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl('*/customer/edit', ['id' => $row->getCustomerId(), 'active_tab' => 'cart']);
    }
}
