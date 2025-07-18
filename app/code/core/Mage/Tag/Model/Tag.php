<?php

/**
 * Maho
 *
 * @package    Mage_Tag
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method Mage_Tag_Model_Resource_Tag _getResource()
 * @method Mage_Tag_Model_Resource_Tag getResource()
 * @method Mage_Tag_Model_Resource_Tag_Collection getCollection()
 * @method Mage_Tag_Model_Resource_Tag_Collection getResourceCollection()
 *
 * @method bool hasBasePopularity()
 * @method int getBasePopularity()
 * @method $this setBasePopularity(int $value)
 * @method int getFirstCustomerId()
 * @method $this setFirstCustomerId(int $value)
 * @method int getFirstStoreId()
 * @method $this setFirstStoreId(int $value)
 * @method $this setName(string $value)
 * @method int getStatus()
 * @method $this setStatus(int $value)
 * @method array getStatusFilter()
 * @method int getStore()
 * @method $this setStore(int $value)
 * @method bool hasStoreId()
 * @method int getStoreId()
 * @method $this setStoreId(int $value)
 * @method array getVisibleInStoreIds()
 * @method $this setVisibleInStoreIds(array $value)
 */
class Mage_Tag_Model_Tag extends Mage_Core_Model_Abstract
{
    public const STATUS_DISABLED = -1;
    public const STATUS_PENDING = 0;
    public const STATUS_APPROVED = 1;

    // statuses for tag relation add
    public const ADD_STATUS_SUCCESS = 'success';
    public const ADD_STATUS_NEW = 'new';
    public const ADD_STATUS_EXIST = 'exist';
    public const ADD_STATUS_REJECTED = 'rejected';

    /**
     * Entity code.
     * Can be used as part of method name for entity processing
     */
    public const ENTITY = 'tag';

    /**
     * Event prefix for observer
     *
     * @var string
     */
    protected $_eventPrefix = 'tag';

    /**
     * This flag means should we or not add base popularity on tag load
     *
     * @var bool
     */
    protected $_addBasePopularity = false;

    #[\Override]
    protected function _construct()
    {
        $this->_init('tag/tag');
    }

    /**
     * Init indexing process after tag data commit
     *
     * @return $this
     */
    #[\Override]
    public function afterCommitCallback()
    {
        parent::afterCommitCallback();
        Mage::getSingleton('index/indexer')->processEntityAction(
            $this,
            self::ENTITY,
            Mage_Index_Model_Event::TYPE_SAVE,
        );
        return $this;
    }

    /**
     * Setter for addBasePopularity flag
     *
     * @param bool $flag
     * @return $this
     */
    public function setAddBasePopularity($flag = true)
    {
        $this->_addBasePopularity = $flag;
        return $this;
    }

    /**
     * Getter for addBasePopularity flag
     *
     * @return bool
     */
    public function getAddBasePopularity()
    {
        return $this->_addBasePopularity;
    }

    /**
     * Product event tags collection getter
     *
     * @return Mage_Tag_Model_Resource_Tag_Collection
     */
    protected function _getProductEventTagsCollection(Varien_Event_Observer $observer)
    {
        return $this->getResourceCollection()
            ->joinRel()
            ->addProductFilter($observer->getEvent()->getProduct()->getId())
            ->addTagGroup()
            ->load();
    }

    /**
     * @return int
     */
    public function getPopularity()
    {
        return $this->_getData('popularity');
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->_getData('name');
    }

    /**
     * @return int
     */
    public function getTagId()
    {
        return $this->_getData('tag_id');
    }

    /**
     * @return int
     */
    public function getRatio()
    {
        return $this->_getData('ratio');
    }

    /**
     * @param int $ratio
     * @return $this
     */
    public function setRatio($ratio)
    {
        $this->setData('ratio', $ratio);
        return $this;
    }

    /**
     * @param string $name
     * @return $this
     */
    public function loadByName($name)
    {
        $this->_getResource()->loadByName($this, $name);
        return $this;
    }

    /**
     * @return $this
     */
    public function aggregate()
    {
        $this->_getResource()->aggregate($this);
        return $this;
    }

    /**
     * @param Varien_Event_Observer $observer
     * @return $this
     */
    public function productEventAggregate($observer)
    {
        $this->_getProductEventTagsCollection($observer)->walk('aggregate');
        return $this;
    }

    /**
     * Product delete event action
     *
     * @param  Varien_Event_Observer $observer
     * @return $this
     */
    public function productDeleteEventAction($observer)
    {
        $this->_getResource()->decrementProducts($this->_getProductEventTagsCollection($observer)->getAllIds());
        return $this;
    }

    /**
     * getter for self::STATUS_APPROVED
     */
    public function getApprovedStatus()
    {
        return self::STATUS_APPROVED;
    }

    /**
     * getter for self::STATUS_PENDING
     */
    public function getPendingStatus()
    {
        return self::STATUS_PENDING;
    }

    /**
     * getter for self::STATUS_DISABLED
     */
    public function getDisabledStatus()
    {
        return self::STATUS_DISABLED;
    }

    /**
     * @return Mage_Tag_Model_Resource_Product_Collection
     */
    public function getEntityCollection()
    {
        return Mage::getResourceModel('tag/product_collection');
    }

    /**
     * @return Mage_Tag_Model_Resource_Customer_Collection
     */
    public function getCustomerCollection()
    {
        return Mage::getResourceModel('tag/customer_collection');
    }

    /**
     * @return string
     */
    public function getTaggedProductsUrl()
    {
        return Mage::getUrl('tag/product/list', ['tagId' => $this->getTagId()]);
    }

    /**
     * @return string
     */
    public function getViewTagUrl()
    {
        return Mage::getUrl('tag/customer/view', ['tagId' => $this->getTagId()]);
    }

    /**
     * @return string
     */
    public function getEditTagUrl()
    {
        return Mage::getUrl('tag/customer/edit', ['tagId' => $this->getTagId()]);
    }

    /**
     * @return string
     */
    public function getRemoveTagUrl()
    {
        return Mage::getUrl('tag/customer/remove', ['tagId' => $this->getTagId()]);
    }

    /**
     * @return Mage_Tag_Model_Resource_Popular_Collection
     */
    public function getPopularCollection()
    {
        return Mage::getResourceModel('tag/popular_collection');
    }

    /**
     * Retrieves array of related product IDs
     *
     * @return array
     */
    public function getRelatedProductIds()
    {
        return Mage::getModel('tag/tag_relation')
            ->setTagId($this->getTagId())
            ->setStoreId($this->getStoreId())
            ->setStatusFilter($this->getStatusFilter())
            ->setCustomerId(null)
            ->getProductIds();
    }

    /**
     * Checks is available current tag in specified store
     *
     * @param int $storeId
     * @return bool
     */
    public function isAvailableInStore($storeId = null)
    {
        $storeId = (is_null($storeId)) ? Mage::app()->getStore()->getId() : $storeId;
        return in_array($storeId, $this->getVisibleInStoreIds());
    }

    /**
     * @return Mage_Core_Model_Abstract
     * @throws Mage_Core_Exception
     */
    #[\Override]
    protected function _beforeDelete()
    {
        $this->_protectFromNonAdmin();
        return parent::_beforeDelete();
    }

    /**
     * Save tag relation with product, customer and store
     *
     * @param int $productId
     * @param int $customerId
     * @param int $storeId
     * @return string - relation add status
     */
    public function saveRelation($productId, $customerId, $storeId)
    {
        /** @var Mage_Tag_Model_Tag_Relation $relationModel */
        $relationModel = Mage::getModel('tag/tag_relation');
        $relationModel->setTagId($this->getId())
            ->setStoreId($storeId)
            ->setProductId($productId)
            ->setCustomerId($customerId)
            ->setActive(Mage_Tag_Model_Tag_Relation::STATUS_ACTIVE)
            ->setCreatedAt($relationModel->getResource()->formatDate(time()));

        $result = '';
        $relationModelSaveNeed = false;
        switch ($this->getStatus()) {
            case $this->getApprovedStatus():
                if ($this->_checkLinkBetweenTagProduct($relationModel)) {
                    $relation = $this->_getLinkBetweenTagCustomerProduct($relationModel);
                    if ($relation->getId()) {
                        if (!$relation->getActive()) {
                            // activate relation if it was inactive
                            $relationModel->setId($relation->getId());
                            $relationModelSaveNeed = true;
                        }
                    } else {
                        $relationModelSaveNeed = true;
                    }
                    $result = self::ADD_STATUS_EXIST;
                } else {
                    $relationModelSaveNeed = true;
                    $result = self::ADD_STATUS_SUCCESS;
                }
                break;
            case $this->getPendingStatus():
                $relation = $this->_getLinkBetweenTagCustomerProduct($relationModel);
                if ($relation->getId()) {
                    if (!$relation->getActive()) {
                        $relationModel->setId($relation->getId());
                        $relationModelSaveNeed = true;
                    }
                } else {
                    $relationModelSaveNeed = true;
                }
                $result = self::ADD_STATUS_NEW;
                break;
            case $this->getDisabledStatus():
                if ($this->_checkLinkBetweenTagCustomerProduct($relationModel)) {
                    $result = self::ADD_STATUS_REJECTED;
                } else {
                    $this->setStatus($this->getPendingStatus())->save();
                    $relationModelSaveNeed = true;
                    $result = self::ADD_STATUS_NEW;
                }
                break;
        }
        if ($relationModelSaveNeed) {
            $relationModel->save();
        }

        return $result;
    }

    /**
     * Check whether product is already marked in store with tag
     *
     * @param Mage_Tag_Model_Tag_Relation $relationModel
     * @return bool
     */
    protected function _checkLinkBetweenTagProduct($relationModel)
    {
        $customerId = $relationModel->getCustomerId();
        $relationModel->setCustomerId(null);
        $result = in_array($relationModel->getProductId(), $relationModel->getProductIds());
        $relationModel->setCustomerId($customerId);
        return $result;
    }

    /**
     * Check whether product is already marked in store with tag by customer
     *
     * @param Mage_Tag_Model_Tag_Relation $relationModel
     * @return bool
     */
    protected function _checkLinkBetweenTagCustomerProduct($relationModel)
    {
        return (count($this->_getLinkBetweenTagCustomerProduct($relationModel)->getProductIds()) > 0);
    }

    /**
     * Get relation model for product marked in store with tag by customer
     *
     * @param Mage_Tag_Model_Tag_Relation $relationModel
     * @return Mage_Tag_Model_Tag_Relation
     */
    protected function _getLinkBetweenTagCustomerProduct($relationModel)
    {
        return Mage::getModel('tag/tag_relation')->loadByTagCustomer(
            $relationModel->getProductId(),
            $this->getId(),
            $relationModel->getCustomerId(),
            $relationModel->getStoreId(),
        );
    }

    /**
     * Processing object after save data
     *
     * @return Mage_Core_Model_Abstract
     */
    #[\Override]
    protected function _afterSave()
    {
        if ($this->hasData('tag_assigned_products')) {
            $tagRelationModel = Mage::getModel('tag/tag_relation');
            $tagRelationModel->addRelations($this, $this->getData('tag_assigned_products'));
        }

        return parent::_afterSave();
    }
}
