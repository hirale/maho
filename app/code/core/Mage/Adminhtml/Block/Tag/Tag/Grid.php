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

use Mage_Adminhtml_Block_Widget_Grid_Massaction_Abstract as MassAction;

/**
 * Adminhtml all tags grid
 *
 * @package    Mage_Adminhtml
 *
 * @method Mage_Tag_Model_Resource_Tag_Collection getCollection()
 */
class Mage_Adminhtml_Block_Tag_Tag_Grid extends Mage_Adminhtml_Block_Widget_Grid
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('tag_tag_grid')
             ->setDefaultSort('name')
             ->setDefaultDir('ASC')
             ->setUseAjax(true)
             ->setSaveParametersInSession(true);
    }

    /**
     * @param Mage_Adminhtml_Block_Widget_Grid_Column $column
     * @return $this
     */
    #[\Override]
    protected function _addColumnFilterToCollection($column)
    {
        if ($column->getIndex() === 'stores') {
            $this->getCollection()->addStoreFilter($column->getFilter()->getCondition(), false);
        } else {
            parent::_addColumnFilterToCollection($column);
        }
        return $this;
    }

    /**
     * @throws Mage_Core_Model_Store_Exception
     */
    #[\Override]
    protected function _prepareCollection()
    {
        $collection = Mage::getResourceModel('tag/tag_collection')
            ->addSummary(Mage::app()->getStore()->getId())
            ->addStoresVisibility();
        $this->setCollection($collection);
        return parent::_prepareCollection();
    }

    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('name', [
            'header'        => Mage::helper('tag')->__('Tag'),
            'index'         => 'name',
        ]);

        $this->addColumn('products', [
            'header'        => Mage::helper('tag')->__('Products'),
            'width'         => 140,
            'index'         => 'products',
            'type'          => 'number',
        ]);

        $this->addColumn('customers', [
            'header'        => Mage::helper('tag')->__('Customers'),
            'width'         => 140,
            'index'         => 'customers',
            'type'          => 'number',
        ]);

        /** @var Mage_Tag_Helper_Data $helper */
        $helper = $this->helper('tag/data');
        $this->addColumn('status', [
            'header'        => Mage::helper('tag')->__('Status'),
            'width'         => 90,
            'index'         => 'status',
            'type'          => 'options',
            'options'       => $helper->getStatusesArray(),
        ]);

        if (!Mage::app()->isSingleStoreMode()) {
            $this->addColumn('visible_in', [
                'header'                => Mage::helper('tag')->__('Store View'),
                'type'                  => 'store',
                'skipAllStoresLabel'    => true,
                'index'                 => 'stores',
                'sortable'              => false,
                'store_view'            => true,
            ]);
        }

        return parent::_prepareColumns();
    }

    /**
     * @return $this
     */
    #[\Override]
    protected function _prepareMassaction()
    {
        $this->setMassactionIdField('tag_id');
        $this->getMassactionBlock()->setFormFieldName('tag');

        $this->getMassactionBlock()->addItem(MassAction::DELETE, [
            'label'    => Mage::helper('tag')->__('Delete'),
            'url'      => $this->getUrl('*/*/massDelete'),
        ]);

        /** @var Mage_Tag_Helper_Data $helper */
        $helper = $this->helper('tag/data');
        $statuses = $helper->getStatusesOptionsArray();

        array_unshift($statuses, ['label' => '', 'value' => '']);

        $this->getMassactionBlock()->addItem(MassAction::STATUS, [
            'label' => Mage::helper('tag')->__('Change status'),
            'url'  => $this->getUrl('*/*/massStatus', ['_current' => true]),
            'additional' => [
                'visibility' => [
                    'name'     => 'status',
                    'type'     => 'select',
                    'class'    => 'required-entry',
                    'label'    => Mage::helper('tag')->__('Status'),
                    'values'   => $statuses,
                ],
            ],
        ]);

        return $this;
    }

    /**
     * Retrieves Grid Url
     *
     * @return string
     */
    #[\Override]
    public function getGridUrl()
    {
        return $this->getUrl('*/tag/ajaxGrid', ['_current' => true]);
    }

    /**
     * Retrieves row click URL
     *
     * @param  Mage_Tag_Model_Tag $row
     * @return string
     */
    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl('*/*/edit', ['tag_id' => $row->getId()]);
    }
}
