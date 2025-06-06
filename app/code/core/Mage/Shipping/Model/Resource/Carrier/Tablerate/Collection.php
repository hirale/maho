<?php

/**
 * Maho
 *
 * @package    Mage_Shipping
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Shipping_Model_Resource_Carrier_Tablerate_Collection extends Mage_Core_Model_Resource_Db_Collection_Abstract
{
    /**
     * directory/country table name
     *
     * @var string
     */
    protected $_countryTable;

    /**
     * directory/country_region table name
     *
     * @var string
     */
    protected $_regionTable;

    /**
     * Define resource model and item
     *
     */
    #[\Override]
    protected function _construct()
    {
        $this->_init('shipping/carrier_tablerate');
        $this->_countryTable    = $this->getTable('directory/country');
        $this->_regionTable     = $this->getTable('directory/country_region');
    }

    /**
     * Initialize select, add country iso3 code and region name
     *
     * @return $this
     */
    #[\Override]
    public function _initSelect()
    {
        parent::_initSelect();

        $this->_select
            ->joinLeft(
                ['country_table' => $this->_countryTable],
                'country_table.country_id = main_table.dest_country_id',
                ['dest_country' => 'iso3_code'],
            )
            ->joinLeft(
                ['region_table' => $this->_regionTable],
                'region_table.region_id = main_table.dest_region_id',
                ['dest_region' => 'code'],
            );

        $this->addOrder('dest_country', self::SORT_ORDER_ASC);
        $this->addOrder('dest_region', self::SORT_ORDER_ASC);
        $this->addOrder('dest_zip', self::SORT_ORDER_ASC);
        $this->addOrder('condition_value', self::SORT_ORDER_ASC);

        return $this;
    }

    /**
     * Add website filter to collection
     *
     * @param int $websiteId
     * @return $this
     */
    public function setWebsiteFilter($websiteId)
    {
        return $this->addFieldToFilter('website_id', $websiteId);
    }

    /**
     * Add condition name (code) filter to collection
     *
     * @param string $conditionName
     * @return $this
     */
    public function setConditionFilter($conditionName)
    {
        return $this->addFieldToFilter('condition_name', $conditionName);
    }

    /**
     * Add country filter to collection
     *
     * @param string $countryId
     * @return $this
     */
    public function setCountryFilter($countryId)
    {
        return $this->addFieldToFilter('dest_country_id', $countryId);
    }
}
