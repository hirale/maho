<?php

/**
 * Maho
 *
 * @package    Mage_CatalogInventory
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_CatalogInventory_Model_Api2_Stock_Item_Validator_Item extends Mage_Api2_Model_Resource_Validator_Fields
{
    /**
     * Validate data.
     * If fails validation, then this method returns false, and
     * getErrors() will return an array of errors that explain why the
     * validation failed.
     *
     * @return bool
     */
    public function isValidSingleItemDataForMultiUpdate(array $data)
    {
        // Validate item id
        if (!isset($data['item_id']) || !is_numeric($data['item_id'])) {
            $this->_addError('Invalid value for "item_id" in request.');
        } else {
            // Validate Stock Item
            /** @var Mage_CatalogInventory_Model_Stock_Item $stockItem */
            $stockItem = Mage::getModel('cataloginventory/stock_item')->load($data['item_id']);
            if (!$stockItem->getId()) {
                $this->_addError(sprintf('StockItem #%d not found.', $data['item_id']));
            } else {
                parent::isValidData($data);
            }
        }
        return !count($this->getErrors());
    }
}
