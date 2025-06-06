<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method Mage_Core_Model_Store_Group getItemById(int $value)
 * @method Mage_Core_Model_Store_Group[] getItems()
 */
class Mage_Core_Model_Resource_Store_Group_Collection extends Mage_Core_Model_Resource_Db_Collection_Abstract
{
    /**
     * Load default flag
     *
     * @deprecated since 1.5.0.0
     * @var bool
     */
    protected $_loadDefault = false;

    /**
     * Define resource model
     *
     */
    #[\Override]
    protected function _construct()
    {
        $this->setFlag('load_default_store_group', false);
        $this->_init('core/store_group');
    }

    /**
     * Set flag for load default (admin) store
     *
     * @param bool $loadDefault
     *
     * @return $this
     */
    public function setLoadDefault($loadDefault)
    {
        return $this->setFlag('load_default_store_group', (bool) $loadDefault);
    }

    /**
     * Is load default (admin) store
     *
     * @return bool
     */
    public function getLoadDefault()
    {
        return $this->getFlag('load_default_store_group');
    }

    /**
     * Add disable default store group filter to collection
     *
     * @return $this
     */
    public function setWithoutDefaultFilter()
    {
        return $this->addFieldToFilter('main_table.group_id', ['gt' => 0]);
    }

    /**
     * Filter to discard stores without views
     *
     * @return $this
     */
    public function setWithoutStoreViewFilter()
    {
        return $this->addFieldToFilter('main_table.default_store_id', ['gt' => 0]);
    }

    #[\Override]
    public function _beforeLoad()
    {
        if (!$this->getLoadDefault()) {
            $this->setWithoutDefaultFilter();
        }
        $this->addOrder('main_table.name', self::SORT_ORDER_ASC);
        return parent::_beforeLoad();
    }

    /**
     * Convert collection items to array for select options
     *
     * @return array
     */
    #[\Override]
    public function toOptionArray()
    {
        return $this->_toOptionArray('group_id', 'name');
    }

    /**
     * Add filter by website to collection
     *
     * @param int|array $website
     *
     * @return $this
     */
    public function addWebsiteFilter($website)
    {
        return $this->addFieldToFilter('main_table.website_id', ['in' => $website]);
    }
}
