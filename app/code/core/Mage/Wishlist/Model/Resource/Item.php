<?php

/**
 * Maho
 *
 * @package    Mage_Wishlist
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Wishlist_Model_Resource_Item extends Mage_Core_Model_Resource_Db_Abstract
{
    #[\Override]
    protected function _construct()
    {
        $this->_init('wishlist/item', 'wishlist_item_id');
    }

    /**
     * Load item by wishlist, product and shared stores
     *
     * @param Mage_Wishlist_Model_Item $object
     * @param int $wishlistId
     * @param int $productId
     * @param array $sharedStores
     * @return $this
     */
    public function loadByProductWishlist($object, $wishlistId, $productId, $sharedStores)
    {
        $adapter = $this->_getReadAdapter();
        $storeWhere = $adapter->quoteInto('store_id IN (?)', $sharedStores);
        $select  = $adapter->select()
            ->from($this->getMainTable())
            ->where('wishlist_id=:wishlist_id AND '
                . 'product_id=:product_id AND '
                . $storeWhere);
        $bind = [
            'wishlist_id' => $wishlistId,
            'product_id'  => $productId,
        ];
        $data = $adapter->fetchRow($select, $bind);
        if ($data) {
            $object->setData($data);
        }
        $this->_afterLoad($object);

        return $this;
    }
}
