<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Entity_Quote_Address extends Mage_Eav_Model_Entity_Abstract
{
    public function __construct()
    {
        $resource = Mage::getSingleton('core/resource');
        $this->setType('quote_address')->setConnection(
            $resource->getConnection('sales_read'),
            $resource->getConnection('sales_write'),
        );
    }

    /**
     * @return $this
     */
    public function collectTotals(Mage_Sales_Model_Quote_Address $address)
    {
        $attributes = $this->loadAllAttributes()->getAttributesByCode();
        foreach ($attributes as $attrCode => $attr) {
            $backend = $attr->getBackend();
            if (method_exists($backend, 'collectTotals')) {
                $backend->collectTotals($address);
            }
        }
        return $this;
    }

    /**
     * @return $this
     */
    public function fetchTotals(Mage_Sales_Model_Quote_Address $address)
    {
        $attributes = $this->loadAllAttributes()->getAttributesByCode();
        foreach ($attributes as $attrCode => $attr) {
            $frontend = $attr->getFrontend();
            if (method_exists($frontend, 'fetchTotals')) {
                $frontend->fetchTotals($address);
            }
        }

        return $this;
    }
}
