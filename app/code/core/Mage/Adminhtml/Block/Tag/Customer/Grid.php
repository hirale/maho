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

/**
 * Child Of Mage_Adminhtml_Block_Tag_Customer
 *
 * @package    Mage_Adminhtml
 *
 * @method Mage_Tag_Model_Resource_Customer_Collection getCollection()
 */
class Mage_Adminhtml_Block_Tag_Customer_Grid extends Mage_Adminhtml_Block_Widget_Grid
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('tag_customer_grid' . Mage::registry('current_tag')->getId());
        $this->setDefaultSort('name');
        $this->setDefaultDir('ASC');
        $this->setUseAjax(true);
    }

    /**
     * Retrieves Grid Url
     *
     * @return string
     */
    #[\Override]
    public function getGridUrl()
    {
        return $this->getUrl('*/*/customer', ['_current' => true]);
    }

    #[\Override]
    protected function _prepareCollection()
    {
        $tagId = Mage::registry('current_tag')->getId();
        $storeId = Mage::registry('current_tag')->getStoreId();
        $collection = Mage::getModel('tag/tag')
            ->getCustomerCollection()
            ->addTagFilter($tagId)
            ->setCountAttribute('tr.tag_relation_id')
            ->addStoreFilter($storeId)
            ->addGroupByCustomerProduct();

        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    #[\Override]
    protected function _afterLoadCollection()
    {
        $this->getCollection()->addProductName();
        return parent::_afterLoadCollection();
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('customer_id', [
            'header'        => Mage::helper('tag')->__('ID'),
            'width'         => 50,
            'align'         => 'right',
            'index'         => 'entity_id',
        ]);

        $this->addColumn('firstname', [
            'header'    => Mage::helper('tag')->__('First Name'),
            'index'     => 'firstname',
        ]);

        $this->addColumn('middlename', [
            'header'    => Mage::helper('tag')->__('Middle Name'),
            'index'     => 'middlename',
        ]);

        $this->addColumn('lastname', [
            'header'    => Mage::helper('tag')->__('Last Name'),
            'index'     => 'lastname',
        ]);

        $this->addColumn('product', [
            'header'    => Mage::helper('tag')->__('Product Name'),
            'filter'    => false,
            'sortable'  => false,
            'index'     => 'product',
        ]);

        $this->addColumn('product_sku', [
            'header'    => Mage::helper('tag')->__('Product SKU'),
            'filter'    => false,
            'sortable'  => false,
            'width'     => 50,
            'align'     => 'right',
            'index'     => 'product_sku',
        ]);

        return parent::_prepareColumns();
    }

    /**
     * @param Varien_Object $row
     * @return string
     */
    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl('*/customer/edit', ['id' => $row->getId()]);
    }
}
