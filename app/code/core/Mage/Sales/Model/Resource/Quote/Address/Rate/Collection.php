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

class Mage_Sales_Model_Resource_Quote_Address_Rate_Collection extends Mage_Core_Model_Resource_Db_Collection_Abstract
{
    /**
     * Whether to load fixed items only
     *
     * @var bool
     */
    protected $_allowFixedOnly   = false;

    #[\Override]
    protected function _construct()
    {
        $this->_init('sales/quote_address_rate');
    }

    /**
     * Set filter by address id
     *
     * @param int $addressId
     * @return $this
     */
    public function setAddressFilter($addressId)
    {
        if ($addressId) {
            $this->addFieldToFilter('address_id', $addressId);
        } else {
            $this->_totalRecords = 0;
            $this->_setIsLoaded(true);
        }
        return $this;
    }

    /**
     * Setter for loading fixed items only
     *
     * @param bool $value
     * @return $this
     */
    public function setFixedOnlyFilter($value)
    {
        $this->_allowFixedOnly = (bool) $value;
        return $this;
    }

    /**
     * Don't add item to the collection if only fixed are allowed and its carrier is not fixed
     * @throws Exception
     */
    #[\Override]
    public function addItem(Varien_Object $rate)
    {
        if ($this->_allowFixedOnly && (!$rate->getCarrierInstance() || !$rate->getCarrierInstance()->isFixed())) {
            return $this;
        }
        return parent::addItem($rate);
    }
}
