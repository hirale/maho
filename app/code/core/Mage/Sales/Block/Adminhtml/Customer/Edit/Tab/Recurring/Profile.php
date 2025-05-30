<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Block_Adminhtml_Customer_Edit_Tab_Recurring_Profile extends Mage_Sales_Block_Adminhtml_Recurring_Profile_Grid implements Mage_Adminhtml_Block_Widget_Tab_Interface
{
    /**
     * Disable filters and paging
     *
     */
    public function __construct()
    {
        parent::__construct();
        $this->setId('customer_edit_tab_recurring_profile');
    }

    /**
     * Return Tab label
     *
     * @return string
     */
    #[\Override]
    public function getTabLabel()
    {
        return $this->__('Recurring Profiles (beta)');
    }

    /**
     * Return Tab title
     *
     * @return string
     */
    #[\Override]
    public function getTabTitle()
    {
        return $this->__('Recurring Profiles (beta)');
    }

    /**
     * Can show tab in tabs
     *
     * @return bool
     */
    #[\Override]
    public function canShowTab()
    {
        $customer = Mage::registry('current_customer');
        return (bool) $customer->getId();
    }

    /**
     * Tab is hidden
     *
     * @return bool
     */
    #[\Override]
    public function isHidden()
    {
        return false;
    }

    /**
     * Prepare collection for grid
     *
     * @return Mage_Adminhtml_Block_Widget_Grid
     */
    #[\Override]
    protected function _prepareCollection()
    {
        $collection = Mage::getResourceModel('sales/recurring_profile_collection')
            ->addFieldToFilter('customer_id', Mage::registry('current_customer')->getId());
        if (!$this->getParam($this->getVarNameSort())) {
            $collection->setOrder('profile_id', 'desc');
        }
        $this->setCollection($collection);
        return Mage_Adminhtml_Block_Widget_Grid::_prepareCollection();
    }

    /**
     * Defines after which tab, this tab should be rendered
     *
     * @return string
     */
    public function getAfter()
    {
        return 'orders';
    }

    /**
     * Return grid url
     *
     * @return string
     */
    #[\Override]
    public function getGridUrl()
    {
        return $this->getUrl('*/sales_recurring_profile/customerGrid', ['_current' => true]);
    }
}
