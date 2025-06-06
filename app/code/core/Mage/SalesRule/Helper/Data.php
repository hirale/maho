<?php

/**
 * Maho
 *
 * @package    Mage_SalesRule
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_SalesRule_Helper_Data extends Mage_Core_Helper_Abstract
{
    protected $_moduleName = 'Mage_SalesRule';

    /**
     * Set store and base price which will be used during discount calculation to item object
     *
     * @param   float $basePrice
     * @param   float $price
     * @return  $this
     */
    public function setItemDiscountPrices(Mage_Sales_Model_Quote_Item_Abstract $item, $basePrice, $price)
    {
        $item->setDiscountCalculationPrice($price);
        $item->setBaseDiscountCalculationPrice($basePrice);
        return $this;
    }

    /**
     * Add additional amounts to discount calculation prices
     *
     * @param   float $basePrice
     * @param   float $price
     * @return  $this
     */
    public function addItemDiscountPrices(Mage_Sales_Model_Quote_Item_Abstract $item, $basePrice, $price)
    {
        $discountPrice      = $item->getDiscountCalculationPrice();
        $baseDiscountPrice  = $item->getBaseDiscountCalculationPrice();

        if ($discountPrice || $baseDiscountPrice || $basePrice || $price) {
            $discountPrice      = $discountPrice ?: $item->getCalculationPrice();
            $baseDiscountPrice  = $baseDiscountPrice ?: $item->getBaseCalculationPrice();
            $this->setItemDiscountPrices($item, $baseDiscountPrice + $basePrice, $discountPrice + $price);
        }
        return $this;
    }
}
