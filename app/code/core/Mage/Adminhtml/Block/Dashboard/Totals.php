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

class Mage_Adminhtml_Block_Dashboard_Totals extends Mage_Adminhtml_Block_Dashboard_Bar
{
    #[\Override]
    protected function _construct()
    {
        parent::_construct();
        $this->setTemplate('dashboard/totalbar.phtml');
    }

    #[\Override]
    protected function _prepareLayout()
    {
        if (!$this->isModuleEnabled('Mage_Reports')) {
            return $this;
        }
        $isFilter = $this->getRequest()->getParam('store') || $this->getRequest()->getParam('website') || $this->getRequest()->getParam('group');
        $period = $this->getRequest()->getParam('period', '24h');

        /** @var Mage_Reports_Model_Resource_Order_Collection $collection */
        $collection = Mage::getResourceModel('reports/order_collection')
            ->addCreateAtPeriodFilter($period)
            ->calculateTotals($isFilter);

        if ($this->getRequest()->getParam('store')) {
            $collection->addFieldToFilter('store_id', $this->getRequest()->getParam('store'));
        } elseif ($this->getRequest()->getParam('website')) {
            $storeIds = Mage::app()->getWebsite($this->getRequest()->getParam('website'))->getStoreIds();
            $collection->addFieldToFilter('store_id', ['in' => $storeIds]);
        } elseif ($this->getRequest()->getParam('group')) {
            $storeIds = Mage::app()->getGroup($this->getRequest()->getParam('group'))->getStoreIds();
            $collection->addFieldToFilter('store_id', ['in' => $storeIds]);
        } elseif (!$collection->isLive()) {
            $collection->addFieldToFilter(
                'store_id',
                ['eq' => Mage::app()->getStore(Mage_Core_Model_Store::ADMIN_CODE)->getId()],
            );
        }

        $collection->load();

        $totals = $collection->getFirstItem();

        $this->addTotal($this->__('Revenue'), $totals->getRevenue());
        $this->addTotal($this->__('Tax'), $totals->getTax());
        $this->addTotal($this->__('Shipping'), $totals->getShipping());
        $this->addTotal($this->__('Quantity'), $totals->getQuantity() * 1, true);
        return $this;
    }
}
