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

class Mage_Sales_Model_Order_Shipment_Api_V2 extends Mage_Sales_Model_Order_Shipment_Api
{
    /**
     * @param array $data
     * @return array
     */
    protected function _prepareItemQtyData($data)
    {
        $_data = [];
        foreach ($data as $item) {
            if (isset($item->order_item_id) && isset($item->qty)) {
                $_data[$item->order_item_id] = $item->qty;
            }
        }
        return $_data;
    }

    /**
     * Create new shipment for order
     *
     * @param string $orderIncrementId
     * @param array $itemsQty
     * @param string $comment
     * @param bool $notifyCustomer
     * @param bool $includeComment
     * @return string|null
     */
    #[\Override]
    public function create(
        $orderIncrementId,
        $itemsQty = [],
        $comment = null,
        $notifyCustomer = false,
        $includeComment = false,
    ) {
        $order = Mage::getModel('sales/order')->loadByIncrementId($orderIncrementId);
        $itemsQty = $this->_prepareItemQtyData($itemsQty);
        /**
          * Check order existing
          */
        if (!$order->getId()) {
            $this->_fault('order_not_exists');
        }

        /**
         * Check shipment create availability
         */
        if (!$order->canShip()) {
            $this->_fault('data_invalid', Mage::helper('sales')->__('Cannot do shipment for order.'));
        }

        /** @var Mage_Sales_Model_Order_Shipment $shipment */
        $shipment = $order->prepareShipment($itemsQty);
        if ($shipment) {
            $shipment->register();
            $shipment->addComment($comment, $notifyCustomer && $includeComment);
            if ($notifyCustomer) {
                $shipment->setEmailSent(true);
            }
            $shipment->getOrder()->setIsInProcess(true);
            try {
                $transactionSave = Mage::getModel('core/resource_transaction')
                    ->addObject($shipment)
                    ->addObject($shipment->getOrder())
                    ->save();
                $shipment->sendEmail($notifyCustomer, ($includeComment ? $comment : ''));
            } catch (Mage_Core_Exception $e) {
                $this->_fault('data_invalid', $e->getMessage());
            }
            return $shipment->getIncrementId();
        }
        return null;
    }

    /**
     * Retrieve allowed shipping carriers for specified order
     *
     * @param string $orderIncrementId
     * @return array
     */
    #[\Override]
    public function getCarriers($orderIncrementId)
    {
        $order = Mage::getModel('sales/order')->loadByIncrementId($orderIncrementId);

        /**
          * Check order existing
          */
        if (!$order->getId()) {
            $this->_fault('order_not_exists');
        }
        $carriers = [];
        foreach ($this->_getCarriers($order) as $key => $value) {
            $carriers[] = ['key' => $key, 'value' => $value];
        }

        return $carriers;
    }
}
