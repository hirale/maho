<?php

/**
 * Maho
 *
 * @package    Mage_Paypal
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Paypal_Model_System_Config_Source_BmlPosition
{
    /**
     * Bml positions source getter for Home Page
     *
     * @return array
     */
    public function getBmlPositionsHP()
    {
        return [
            '0' => Mage::helper('paypal')->__('Header (center)'),
            '1' => Mage::helper('paypal')->__('Sidebar (right)'),
        ];
    }

    /**
     * Bml positions source getter for Catalog Category Page
     *
     * @return array
     */
    public function getBmlPositionsCCP()
    {
        return [
            '0' => Mage::helper('paypal')->__('Header (center)'),
            '1' => Mage::helper('paypal')->__('Sidebar (right)'),
        ];
    }

    /**
     * Bml positions source getter for Catalog Product Page
     *
     * @return array
     */
    public function getBmlPositionsCPP()
    {
        return [
            '0' => Mage::helper('paypal')->__('Header (center)'),
            '1' => Mage::helper('paypal')->__('Near Paypal Credit checkout button'),
        ];
    }

    /**
     * Bml positions source getter for Checkout Cart Page
     *
     * @return array
     */
    public function getBmlPositionsCheckout()
    {
        return [
            '0' => Mage::helper('paypal')->__('Header (center)'),
            '1' => Mage::helper('paypal')->__('Near Paypal Credit checkout button'),
        ];
    }
}
