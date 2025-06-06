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
 * @method Mage_Sales_Model_Order_Shipment_Item getItemById(int $value)
 * @method Mage_Sales_Model_Order_Shipment_Item[] getItems()
 */
class Mage_Sales_Model_Resource_Order_Shipment_Item_Collection extends Mage_Sales_Model_Resource_Collection_Abstract
{
    /**
     * @var string
     */
    protected $_eventPrefix    = 'sales_order_shipment_item_collection';

    /**
     * @var string
     */
    protected $_eventObject    = 'order_shipment_item_collection';

    #[\Override]
    protected function _construct()
    {
        $this->_init('sales/order_shipment_item');
    }

    /**
     * Set shipment filter
     *
     * @param int $shipmentId
     * @return $this
     */
    public function setShipmentFilter($shipmentId)
    {
        $this->addFieldToFilter('parent_id', $shipmentId);
        return $this;
    }
}
