<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Catalog_Model_Api2_Product_Rest_Guest_V1 extends Mage_Catalog_Model_Api2_Product_Rest
{
    /**
     * Get customer group
     *
     * @return int
     */
    #[\Override]
    protected function _getCustomerGroupId()
    {
        return Mage_Customer_Model_Group::NOT_LOGGED_IN_ID;
    }

    /**
     * Define product price with or without taxes
     *
     * @param float $price
     * @param bool $withTax
     * @return float
     */
    #[\Override]
    protected function _applyTaxToPrice($price, $withTax = true)
    {
        return $this->_getPrice($price, $withTax);
    }
}
