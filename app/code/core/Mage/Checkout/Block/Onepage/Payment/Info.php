<?php

/**
 * Maho
 *
 * @package    Mage_Checkout
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Checkout_Block_Onepage_Payment_Info extends Mage_Payment_Block_Info_Container
{
    /**
     * Retrieve payment info model
     *
     * @return Mage_Payment_Model_Info|false
     */
    #[\Override]
    public function getPaymentInfo()
    {
        $info = Mage::getSingleton('checkout/session')->getQuote()->getPayment();
        if ($info->getMethod()) {
            return $info;
        }
        return false;
    }

    /**
     * @return string
     */
    #[\Override]
    protected function _toHtml()
    {
        $html = '';
        if ($block = $this->getChild($this->_getInfoBlockName())) {
            $html = $block->toHtml();
        }
        return $html;
    }
}
