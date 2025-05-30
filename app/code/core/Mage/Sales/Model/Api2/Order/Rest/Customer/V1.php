<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Api2_Order_Rest_Customer_V1 extends Mage_Sales_Model_Api2_Order_Rest
{
    /**
     * Retrieve collection instance for orders
     *
     * @return Mage_Sales_Model_Resource_Order_Collection
     */
    #[\Override]
    protected function _getCollectionForRetrieve()
    {
        return parent::_getCollectionForRetrieve()->addAttributeToFilter(
            'customer_id',
            ['eq' => $this->getApiUser()->getUserId()],
        );
    }

    /**
     * Retrieve collection instance for single order
     *
     * @param int $orderId Order identifier
     * @return Mage_Sales_Model_Resource_Order_Collection
     */
    #[\Override]
    protected function _getCollectionForSingleRetrieve($orderId)
    {
        return parent::_getCollectionForSingleRetrieve($orderId)->addAttributeToFilter(
            'customer_id',
            ['eq' => $this->getApiUser()->getUserId()],
        );
    }

    /**
     * Prepare and return order comments collection
     *
     * @param array $orderIds Orders' identifiers
     * @return Mage_Sales_Model_Resource_Order_Status_History_Collection|Object
     */
    #[\Override]
    protected function _getCommentsCollection(array $orderIds)
    {
        return parent::_getCommentsCollection($orderIds)->addFieldToFilter('is_visible_on_front', 1);
    }
}
