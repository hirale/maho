<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Adminhtml customer orders grid block
 *
 * @package    Mage_Adminhtml
 *
 * @method Mage_Wishlist_Model_Resource_Item_Collection getCollection()
 */
class Mage_Adminhtml_Block_Customer_Edit_Tab_Wishlist extends Mage_Adminhtml_Block_Widget_Grid
{
    /**
     * Default sort field
     *
     * @var string
     */
    protected $_defaultSort = 'added_at';

    /**
     * Parent template name
     *
     * @var string
     */
    protected $_parentTemplate;

    /**
     * List of helpers to show options for product cells
     */
    protected $_productHelpers = [];

    /**
     * Initialize Grid
     *
     */
    public function __construct()
    {
        parent::__construct();
        $this->setId('wishlistGrid');
        $this->setUseAjax(true);
        $this->_parentTemplate = $this->getTemplate();
        $this->setTemplate('customer/tab/wishlist.phtml');
        $this->setEmptyText(Mage::helper('customer')->__('No Items Found'));
        $this->addProductConfigurationHelper('default', 'catalog/product_configuration');
    }

    /**
     * Create customer wishlist item collection
     *
     * @return Mage_Wishlist_Model_Resource_Item_Collection
     */
    protected function _createCollection()
    {
        return Mage::getModel('wishlist/item')->getCollection()
            ->setWebsiteId($this->_getCustomer()->getWebsiteId())
            ->setCustomerGroupId($this->_getCustomer()->getGroupId());
    }

    /**
     * Prepare customer wishlist product collection
     *
     * @return $this
     */
    #[\Override]
    protected function _prepareCollection()
    {
        $customer = Mage::registry('current_customer');
        $storeIds = Mage::app()->getWebsite($this->getWebsiteId())->getStoreIds();

        $wishlist = Mage::getModel('wishlist/wishlist')
            ->setSharedStoreIds($storeIds)
            ->loadByCustomer($customer, true);

        if ($wishlist) {
            $collection = $wishlist->getItemsCollection();
        } else {
            $collection = new Varien_Data_Collection();
        }

        $collection
            ->setWebsiteId($this->_getCustomer()->getWebsiteId())
            ->setCustomerGroupId($this->_getCustomer()->getGroupId())
            ->resetSortOrder()
            ->setDaysInWishlist(true)
            ->addStoreData();

        $this->setCollection($collection);

        return parent::_prepareCollection();
    }

    /**
     * Prepare Grid columns
     *
     * @return $this
     */
    #[\Override]
    protected function _prepareColumns()
    {
        $this->addColumn('product_name', [
            'header'    => Mage::helper('catalog')->__('Product Name'),
            'index'     => 'product_name',
            'renderer'  => 'adminhtml/customer_edit_tab_view_grid_renderer_item',
        ]);

        $this->addColumn('description', [
            'header'    => Mage::helper('wishlist')->__('User Description'),
            'index'     => 'description',
            'renderer'  => 'adminhtml/customer_edit_tab_wishlist_grid_renderer_description',
        ]);

        $this->addColumn('qty', [
            'header'    => Mage::helper('catalog')->__('Qty'),
            'index'     => 'qty',
            'type'      => 'number',
        ]);

        if (!Mage::app()->isSingleStoreMode()) {
            $this->addColumn('store', [
                'header'    => Mage::helper('wishlist')->__('Added From'),
                'type'      => 'store',
            ]);
        }

        $this->addColumn('added_at', [
            'header'    => Mage::helper('wishlist')->__('Date Added'),
            'index'     => 'added_at',
            'gmtoffset' => true,
            'type'      => 'date',
        ]);

        $this->addColumn('days', [
            'header'    => Mage::helper('wishlist')->__('Days in Wishlist'),
            'index'     => 'days_in_wishlist',
            'type'      => 'number',
        ]);

        $this->addColumn('action', [
            'type'      => 'action',
            'index'     => 'wishlist_item_id',
            'renderer'  => 'adminhtml/customer_grid_renderer_multiaction',
            'actions'   => [
                [
                    'caption'   => Mage::helper('customer')->__('Configure'),
                    'url'       => 'javascript:void(0)',
                    'process'   => 'configurable',
                    'control_object' => 'wishlistControl',
                ],
                [
                    'caption'   => Mage::helper('customer')->__('Delete'),
                    'url'       => '#',
                    'onclick'   => 'return wishlistControl.removeItem($wishlist_item_id);',
                ],
            ],
        ]);

        return parent::_prepareColumns();
    }

    /**
     * Add column filter to collection
     *
     * @param Mage_Adminhtml_Block_Widget_Grid_Column $column
     * @return $this
     */
    #[\Override]
    protected function _addColumnFilterToCollection($column)
    {
        $collection = $this->getCollection();
        $value = $column->getFilter()->getValue();
        if ($collection && $value) {
            match ($column->getId()) {
                'product_name' => $collection->addProductNameFilter($value),
                'store' => $collection->addStoreFilter($value),
                'days' => $collection->addDaysFilter($value),
                default => $collection->addFieldToFilter($column->getIndex(), $column->getFilter()->getCondition()),
            };
        }
        return $this;
    }

    /**
     * Sets sorting order by some column
     *
     * @param Mage_Adminhtml_Block_Widget_Grid_Column $column
     * @return $this
     */
    #[\Override]
    protected function _setCollectionOrder($column)
    {
        $collection = $this->getCollection();
        if ($collection) {
            match ($column->getId()) {
                'product_name' => $collection->setOrderByProductName($column->getDir()),
                default => parent::_setCollectionOrder($column),
            };
        }
        return $this;
    }

    /**
     * Retrieve current customer object
     *
     * @return Mage_Customer_Model_Customer
     */
    protected function _getCustomer()
    {
        return Mage::registry('current_customer');
    }

    /**
     * Gets customer assigned to this block
     */
    public function getCustomer(): Mage_Customer_Model_Customer
    {
        return Mage::registry('current_customer');
    }

    /**
     * Retrieve Grid URL
     *
     * @return string
     */
    #[\Override]
    public function getGridUrl()
    {
        return $this->getUrl('*/*/wishlist', ['_current' => true, 'website_id' => $this->getWebsiteId()]);
    }

    /**
     * Retrieve Grid Parent Block HTML
     *
     * @return string
     */
    public function getGridParentHtml()
    {
        $templateName = Mage::getDesign()->getTemplateFilename($this->_parentTemplate, ['_relative' => true]);
        return $this->fetchView($templateName);
    }

    /**
     * Retrieve Row click URL
     *
     * @return string
     */
    #[\Override]
    public function getRowUrl($row)
    {
        return $this->getUrl('*/catalog_product/edit', ['id' => $row->getProductId()]);
    }

    /**
     * Adds product type helper depended on product type (used to show options in item cell)
     *
     * @param string $productType
     * @param string $helperName
     *
     * @return $this
     */
    public function addProductConfigurationHelper($productType, $helperName)
    {
        $this->_productHelpers[$productType] = $helperName;
        return $this;
    }

    /**
     * Returns array of product configuration helpers
     *
     * @return array
     */
    public function getProductConfigurationHelpers()
    {
        return $this->_productHelpers;
    }
}
