<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Sales_Order_Create_Totals_Grandtotal extends Mage_Adminhtml_Block_Sales_Order_Create_Totals_Default
{
    protected $_template = 'sales/order/create/totals/grandtotal.phtml';

    public function includeTax()
    {
        return Mage::getSingleton('tax/config')->displayCartTaxWithGrandTotal();
    }

    public function getTotalExclTax()
    {
        $excl = $this->getTotal()->getAddress()->getGrandTotal() - $this->getTotal()->getAddress()->getTaxAmount();
        $excl = max($excl, 0);
        return $excl;
    }
}
