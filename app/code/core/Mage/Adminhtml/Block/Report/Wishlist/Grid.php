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

class Mage_Adminhtml_Block_Report_Wishlist_Grid extends Mage_Adminhtml_Block_Widget_Grid
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('wishlistReportGrid');
        $this->setDefaultSort('entity_id');
        $this->setDefaultDir('desc');
    }

    #[\Override]
    protected function _prepareCollection()
    {
        $collection = Mage::getResourceModel('reports/wishlist_product_collection')
            ->addAttributeToSelect('entity_id')
            ->addAttributeToSelect('name')
            ->addWishlistCount();

        $this->setCollection($collection);

        parent::_prepareCollection();

        return $this;
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('entity_id', [
            'header'    => Mage::helper('reports')->__('ID'),
            'index'     => 'entity_id',
        ]);

        $this->addColumn('name', [
            'header'    => Mage::helper('reports')->__('Name'),
            'index'     => 'name',
        ]);

        $this->addColumn('wishlists', [
            'header'    => Mage::helper('reports')->__('Wishlists'),
            'width'     => '50px',
            'align'     => 'right',
            'index'     => 'wishlists',
        ]);

        $this->addColumn('bought_from_wishlists', [
            'header'    => Mage::helper('reports')->__('Bought from wishlists'),
            'width'     => '50px',
            'align'     => 'right',
            'sortable'  => false,
            'index'     => 'bought_from_wishlists',
        ]);

        $this->addColumn('w_vs_order', [
            'header'    => Mage::helper('reports')->__('Wishlist vs. Regular Order'),
            'width'     => '50px',
            'align'     => 'right',
            'sortable'  => false,
            'index'     => 'w_vs_order',
        ]);

        $this->addColumn('num_deleted', [
            'header'    => Mage::helper('reports')->__('Number of Times Deleted'),
            'width'     => '50px',
            'align'     => 'right',
            'sortable'  => false,
            'index'     => 'num_deleted',
        ]);

        $this->addExportType('*/*/exportWishlistCsv', Mage::helper('reports')->__('CSV'));
        $this->addExportType('*/*/exportWishlistExcel', Mage::helper('reports')->__('Excel XML'));

        $this->setFilterVisibility(false);

        return parent::_prepareColumns();
    }
}
