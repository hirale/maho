<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Core_Model_Resource_Store_Group extends Mage_Core_Model_Resource_Db_Abstract
{
    #[\Override]
    protected function _construct()
    {
        $this->_init('core/store_group', 'group_id');
    }

    /**
     * Update default store group for website
     *
     * @param Mage_Core_Model_Store_Group $model
     */
    #[\Override]
    protected function _afterSave(Mage_Core_Model_Abstract $model)
    {
        $this->_updateStoreWebsite($model->getId(), $model->getWebsiteId());
        $this->_updateWebsiteDefaultGroup($model->getWebsiteId(), $model->getId());
        $this->_changeWebsite($model);

        return $this;
    }

    /**
     * Update default store group for website
     *
     * @param int $websiteId
     * @param int $groupId
     * @return $this
     */
    protected function _updateWebsiteDefaultGroup($websiteId, $groupId)
    {
        $select = $this->_getWriteAdapter()->select()
            ->from($this->getMainTable(), 'COUNT(*)')
            ->where('website_id = :website');
        $count  = $this->_getWriteAdapter()->fetchOne($select, ['website' => $websiteId]);

        if ($count == 1) {
            $bind  = ['default_group_id' => $groupId];
            $where = ['website_id = ?' => $websiteId];
            $this->_getWriteAdapter()->update($this->getTable('core/website'), $bind, $where);
        }
        return $this;
    }

    /**
     * Change store group website
     *
     * @return $this
     */
    protected function _changeWebsite(Mage_Core_Model_Abstract $model)
    {
        if ($model->getOriginalWebsiteId() && $model->getWebsiteId() != $model->getOriginalWebsiteId()) {
            $select = $this->_getWriteAdapter()->select()
               ->from($this->getTable('core/website'), 'default_group_id')
               ->where('website_id = :website_id');
            $groupId = $this->_getWriteAdapter()->fetchOne($select, ['website_id' => $model->getOriginalWebsiteId()]);

            if ($groupId == $model->getId()) {
                $bind  = ['default_group_id' => 0];
                $where = ['website_id = ?' => $model->getOriginalWebsiteId()];
                $this->_getWriteAdapter()->update($this->getTable('core/website'), $bind, $where);
            }
        }
        return $this;
    }

    /**
     * Update website for stores that assigned to store group
     *
     * @param int $groupId
     * @param int $websiteId
     * @return $this
     */
    protected function _updateStoreWebsite($groupId, $websiteId)
    {
        $bind  = ['website_id' => $websiteId];
        $where = ['group_id = ?' => $groupId];
        $this->_getWriteAdapter()->update($this->getTable('core/store'), $bind, $where);
        return $this;
    }

    /**
     * Save default store for store group
     *
     * @param int $groupId
     * @param int $storeId
     * @return $this
     */
    protected function _saveDefaultStore($groupId, $storeId)
    {
        $bind  = ['default_store_id' => $storeId];
        $where = ['group_id = ?' => $groupId];
        $this->_getWriteAdapter()->update($this->getMainTable(), $bind, $where);

        return $this;
    }
}
