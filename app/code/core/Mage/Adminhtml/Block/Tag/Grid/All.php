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
 * Adminhtml all tags grid block
 *
 * @package    Mage_Adminhtml
 *
 * @method Mage_Tag_Model_Resource_Tag_Collection getCollection()
 */
class Mage_Adminhtml_Block_Tag_Grid_All extends Mage_Adminhtml_Block_Widget_Grid
{
    /**
     * Mage_Adminhtml_Block_Tag_Grid_All constructor.
     */
    public function __construct()
    {
        parent::__construct();
        $this->setId('tagsGrid');
        $this->setDefaultSort('tag_id');
        $this->setDefaultDir('desc');
    }

    #[\Override]
    protected function _prepareCollection()
    {
        $collection = Mage::getResourceModel('tag/tag_collection')->addStoresVisibility();
        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('name', [
            'header'    => Mage::helper('tag')->__('Tag'),
            'index'     => 'name',
        ]);
        $this->addColumn('total_used', [
            'header'    => Mage::helper('tag')->__('# of Uses'),
            'width'     => '140px',
            'align'     => 'center',
            'index'     => 'total_used',
            'type'      => 'number',
        ]);
        $this->addColumn('status', [
            'header'    => Mage::helper('tag')->__('Status'),
            'width'     => '90px',
            'index'     => 'status',
            'type'      => 'options',
            'options'    => [
                Mage_Tag_Model_Tag::STATUS_DISABLED => Mage::helper('tag')->__('Disabled'),
                Mage_Tag_Model_Tag::STATUS_PENDING  => Mage::helper('tag')->__('Pending'),
                Mage_Tag_Model_Tag::STATUS_APPROVED => Mage::helper('tag')->__('Approved'),
            ],
        ]);

        $this->setColumnFilter('id')
            ->setColumnFilter('name')
            ->setColumnFilter('total_used')
        ;

        return parent::_prepareColumns();
    }

    /**
     * @param Mage_Adminhtml_Block_Widget_Grid_Column $column
     * @return $this
     */
    #[\Override]
    protected function _addColumnFilterToCollection($column)
    {
        if ($this->getCollection() && $column->getFilter()->getValue()) {
            if ($column->getIndex() === 'stores') {
                $this->getCollection()->addAttributeToFilter($column->getIndex(), $column->getFilter()->getCondition());
            } else {
                $this->getCollection()->addStoreFilter($column->getFilter()->getCondition());
            }
        }
        return $this;
    }

    /**
     * @param Varien_Object $row
     * @return string
     */
    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl('*/*/products', ['tag_id' => $row->getId()]);
    }
}
