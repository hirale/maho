<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Promo_Catalog_Grid extends Mage_Adminhtml_Block_Widget_Grid
{
    /**
     * Initialize grid
     * Set sort settings
     */
    public function __construct()
    {
        parent::__construct();
        $this->setId('promo_catalog_grid');
        $this->setDefaultSort('name');
        $this->setDefaultDir('ASC');
        $this->setSaveParametersInSession(true);
    }

    /**
     * Add websites to catalog rules collection
     * Set collection
     *
     * @return $this
     */
    #[\Override]
    protected function _prepareCollection()
    {
        /** @var Mage_CatalogRule_Model_Resource_Rule_Collection $collection */
        $collection = Mage::getModel('catalogrule/rule')
            ->getResourceCollection();
        $collection->addWebsitesToResult();
        $this->setCollection($collection);

        parent::_prepareCollection();
        return $this;
    }

    /**
     * Add grid columns
     *
     * @return $this
     */
    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('rule_id', [
            'header'    => Mage::helper('catalogrule')->__('ID'),
            'align'     => 'right',
            'width'     => '50px',
            'index'     => 'rule_id',
        ]);

        $this->addColumn('name', [
            'header'    => Mage::helper('catalogrule')->__('Rule Name'),
            'align'     => 'left',
            'index'     => 'name',
        ]);

        $this->addColumn('from_date', [
            'header'    => Mage::helper('catalogrule')->__('Date Start'),
            'align'     => 'left',
            'type'      => 'date',
            'index'     => 'from_date',
        ]);

        $this->addColumn('to_date', [
            'header'    => Mage::helper('catalogrule')->__('Date Expire'),
            'align'     => 'left',
            'type'      => 'date',
            'default'   => '--',
            'index'     => 'to_date',
        ]);

        $this->addColumn('is_active', [
            'header'    => Mage::helper('catalogrule')->__('Status'),
            'align'     => 'left',
            'width'     => '80px',
            'index'     => 'is_active',
            'type'      => 'options',
            'options'   => [
                1 => Mage::helper('catalogrule')->__('Active'),
                0 => Mage::helper('catalogrule')->__('Inactive'),
            ],
        ]);

        if (!Mage::app()->isSingleStoreMode()) {
            $this->addColumn('rule_website', [
                'header'    => Mage::helper('catalogrule')->__('Website'),
                'align'     => 'left',
                'index'     => 'website_ids',
                'type'      => 'options',
                'sortable'  => false,
                'options'   => Mage::getSingleton('adminhtml/system_store')->getWebsiteOptionHash(),
                'width'     => 200,
            ]);
        }

        parent::_prepareColumns();
        return $this;
    }

    /**
     * Retrieve row click URL
     *
     * @param Mage_CatalogRule_Model_Rule $row
     *
     * @return string
     */
    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl('*/*/edit', ['id' => $row->getRuleId()]);
    }
}
