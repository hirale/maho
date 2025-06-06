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

/**
 * @method Mage_Sales_Model_Order_Shipment getItemById(int $value)
 * @method Mage_Sales_Model_Order_Shipment[] getItems()
 */
class Mage_Sales_Model_Resource_Order_Shipment_Collection extends Mage_Sales_Model_Resource_Order_Collection_Abstract
{
    /**
     * @var string
     */
    protected $_eventPrefix    = 'sales_order_shipment_collection';

    /**
     * @var string
     */
    protected $_eventObject    = 'order_shipment_collection';

    /**
     * Order field for setOrderFilter
     *
     * @var string
     */
    protected $_orderField     = 'order_id';

    #[\Override]
    protected function _construct()
    {
        $this->_init('sales/order_shipment');
    }

    /**
     * Used to emulate after load functionality for each item without loading them
     *
     * @return $this
     */
    #[\Override]
    protected function _afterLoad()
    {
        $this->walk('afterLoad');

        return $this;
    }
}
