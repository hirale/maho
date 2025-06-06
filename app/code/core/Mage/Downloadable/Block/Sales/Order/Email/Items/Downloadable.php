<?php

/**
 * Maho
 *
 * @package    Mage_Downloadable
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Downlaodable Sales Order Email items renderer
 *
 * @package    Mage_Downloadable
 *
 * @method Mage_Downloadable_Model_Link_Purchased_Item getItem()
 */
class Mage_Downloadable_Block_Sales_Order_Email_Items_Downloadable extends Mage_Sales_Block_Order_Email_Items_Default
{
    /**
     * @var Mage_Downloadable_Model_Link_Purchased
     */
    protected $_purchased = null;

    /**
     * @return Mage_Downloadable_Model_Link_Purchased
     */
    public function getLinks()
    {
        $this->_purchased = Mage::getModel('downloadable/link_purchased')
            ->load($this->getItem()->getOrder()->getId(), 'order_id');
        $purchasedLinks = Mage::getModel('downloadable/link_purchased_item')->getCollection()
            ->addFieldToFilter('order_item_id', $this->getItem()->getOrderItem()->getId());
        $this->_purchased->setPurchasedItems($purchasedLinks);

        return $this->_purchased;
    }

    /**
     * @return string
     */
    public function getLinksTitle()
    {
        if ($this->_purchased->getLinkSectionTitle()) {
            return $this->_purchased->getLinkSectionTitle();
        }
        return Mage::getStoreConfig(Mage_Downloadable_Model_Link::XML_PATH_LINKS_TITLE);
    }

    /**
     * @param Mage_Downloadable_Model_Link_Purchased_Item $item
     * @return string
     */
    public function getPurchasedLinkUrl($item)
    {
        return $this->getUrl('downloadable/download/link', [
            'id'        => $item->getLinkHash(),
            '_store'    => $this->getOrder()->getStore(),
            '_secure'   => true,
            '_nosid'    => true,
        ]);
    }
}
