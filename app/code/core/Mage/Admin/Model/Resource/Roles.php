<?php

/**
 * Maho
 *
 * @package    Mage_Admin
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Admin_Model_Resource_Roles extends Mage_Core_Model_Resource_Db_Abstract
{
    /**
     * Users table
     *
     * @var string
     */
    protected $_usersTable;

    /**
     * Rule table
     *
     * @var string
     */
    protected $_ruleTable;

    #[\Override]
    protected function _construct()
    {
        $this->_init('admin/role', 'role_id');

        $this->_usersTable = $this->getTable('admin/user');
        $this->_ruleTable  = $this->getTable('admin/rule');
    }

    /**
     * Process role before saving
     *
     * @return $this
     */
    #[\Override]
    protected function _beforeSave(Mage_Core_Model_Abstract $role)
    {
        if ($role->getId() == '') {
            if ($role->getIdFieldName()) {
                $role->unsetData($role->getIdFieldName());
            } else {
                $role->unsetData('id');
            }
        }

        if ($role->getPid() > 0) {
            $select = $this->_getReadAdapter()->select()
                ->from($this->getMainTable(), ['tree_level'])
                ->where("{$this->getIdFieldName()} = :pid");

            $binds = [
                'pid' => (int) $role->getPid(),
            ];

            $treeLevel = $this->_getReadAdapter()->fetchOne($select, $binds);
        } else {
            $treeLevel = 0;
        }

        $role->setTreeLevel($treeLevel + 1);
        $role->setRoleName($role->getName());

        return $this;
    }

    /**
     * Process role after saving
     *
     * @return $this
     */
    #[\Override]
    protected function _afterSave(Mage_Core_Model_Abstract $role)
    {
        $this->_updateRoleUsersAcl($role);
        Mage::app()->getCache()->clean([Mage_Adminhtml_Block_Page_Menu::CACHE_TAGS]);
        return $this;
    }

    /**
     * Process role after deleting
     *
     * @return $this
     */
    #[\Override]
    protected function _afterDelete(Mage_Core_Model_Abstract $role)
    {
        $adapter = $this->_getWriteAdapter();
        $adapter->delete($this->getMainTable(), ['parent_id = ?' => (int) $role->getId()]);
        $adapter->delete($this->_ruleTable, ['role_id = ?' => (int) $role->getId()]);
        return $this;
    }

    /**
     * Get role users
     *
     * @return array
     */
    public function getRoleUsers(Mage_Admin_Model_Roles $role)
    {
        $adapter = $this->_getReadAdapter();
        $select  = $adapter->select()
            ->from($this->getMainTable(), ['user_id'])
            ->where('parent_id = ?', $role->getId())
            ->where('role_type = ?', Mage_Admin_Model_Acl::ROLE_TYPE_USER)
            ->where('user_id > 0');
        return $adapter->fetchCol($select);
    }

    /**
     * Update role users
     *
     * @return bool
     */
    private function _updateRoleUsersAcl(Mage_Admin_Model_Roles $role)
    {
        $users = $this->getRoleUsers($role);
        $rowsCount = 0;

        if (count($users)) {
            $rowsCount = $this->_getWriteAdapter()->update(
                $this->_usersTable,
                ['reload_acl_flag' => 1],
                ['user_id IN (?)' => $users],
            );
        }

        return $rowsCount > 0;
    }
}
