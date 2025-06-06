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

class Mage_Adminhtml_Block_Dashboard_Grids extends Mage_Adminhtml_Block_Widget_Tabs
{
    public function __construct()
    {
        parent::__construct();
        $this->setId('grid_tab');
        $this->setDestElementId('grid_tab_content');
        $this->setTemplate('widget/tabshoriz.phtml');
    }

    /**
     * Prepare layout for dashboard bottom tabs
     *
     * To load block statically:
     *     1) content must be generated
     *     2) url should not be specified
     *     3) class should not be 'ajax'
     * To load with ajax:
     *     1) do not load content
     *     2) specify url (BE CAREFUL)
     *     3) specify class 'ajax'
     *
     * @return $this
     */
    #[\Override]
    protected function _prepareLayout()
    {
        // load this active tab statically
        $this->addTab('ordered_products', [
            'label'     => $this->__('Bestsellers'),
            'content'   => $this->getLayout()->createBlock('adminhtml/dashboard_tab_products_ordered')->toHtml(),
            'active'    => true,
        ]);

        // load other tabs with ajax
        $this->addTab('reviewed_products', [
            'label'     => $this->__('Most Viewed Products'),
            'url'       => $this->getUrl('*/*/productsViewed', ['_current' => true]),
            'class'     => 'ajax',
        ]);

        $this->addTab('new_customers', [
            'label'     => $this->__('New Customers'),
            'url'       => $this->getUrl('*/*/customersNewest', ['_current' => true]),
            'class'     => 'ajax',
        ]);

        $this->addTab('customers', [
            'label'     => $this->__('Customers'),
            'url'       => $this->getUrl('*/*/customersMost', ['_current' => true]),
            'class'     => 'ajax',
        ]);

        return parent::_prepareLayout();
    }
}
