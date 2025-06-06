<?php

/**
 * Maho
 *
 * @package    Mage_Api2
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Api2_Model_Acl extends Zend_Acl
{
    /**
     * REST ACL roles collection
     *
     * @var Mage_Api2_Model_Resource_Acl_Global_Role_Collection
     */
    protected $_rolesCollection;

    /**
     * API2 config model instance
     *
     * @var Mage_Api2_Model_Config
     */
    protected $_config;

    /**
     * Resource type of request
     *
     * @var string
     */
    protected $_resourceType;

    /**
     * Operation of request
     *
     * @var string
     */
    protected $_operation;

    /**
     * @param array $options
     */
    public function __construct($options)
    {
        if (!isset($options['resource_type']) || empty($options['resource_type'])) {
            throw new Exception("Passed parameter 'resource_type' is wrong.");
        }
        if (!isset($options['operation']) || empty($options['operation'])) {
            throw new Exception("Passed parameter 'operation' is wrong.");
        }
        $this->_resourceType = $options['resource_type'];
        $this->_operation = $options['operation'];

        $this->_setResources();
        $this->_setRoles();
        $this->_setRules();
    }

    /**
     * Retrieve REST ACL roles collection
     *
     * @return Mage_Api2_Model_Resource_Acl_Global_Role_Collection
     */
    protected function _getRolesCollection()
    {
        if ($this->_rolesCollection === null) {
            $this->_rolesCollection = Mage::getResourceModel('api2/acl_global_role_collection');
        }
        return $this->_rolesCollection;
    }

    /**
     * Retrieve API2 config model instance
     *
     * @return Mage_Api2_Model_Config
     */
    protected function _getConfig()
    {
        if ($this->_config === null) {
            $this->_config = Mage::getModel('api2/config');
        }
        return $this->_config;
    }

    /**
     * Retrieve resources types and set into ACL
     *
     * @return $this
     */
    protected function _setResources()
    {
        foreach ($this->_getConfig()->getResourcesTypes() as $type) {
            $this->addResource($type);
        }
        return $this;
    }

    /**
     * Retrieve roles from DB and set into ACL
     *
     * @return $this
     */
    protected function _setRoles()
    {
        /** @var Mage_Api2_Model_Acl_Global_Role $role */
        foreach ($this->_getRolesCollection() as $role) {
            $this->addRole($role->getId());
        }
        return $this;
    }

    /**
     * Retrieve rules data from DB and inject it into ACL
     *
     * @return $this
     */
    protected function _setRules()
    {
        /** @var Mage_Api2_Model_Resource_Acl_Global_Rule_Collection $rulesCollection */
        $rulesCollection = Mage::getResourceModel('api2/acl_global_rule_collection');

        /** @var Mage_Api2_Model_Acl_Global_Rule $rule */
        foreach ($rulesCollection as $rule) {
            if (Mage_Api2_Model_Acl_Global_Rule::RESOURCE_ALL === $rule->getResourceId()) {
                if (in_array($rule->getRoleId(), Mage_Api2_Model_Acl_Global_Role::getSystemRoles())) {
                    /** @var Mage_Api2_Model_Acl_Global_Role $role */
                    $role = $this->_getRolesCollection()->getItemById($rule->getRoleId());
                    $privileges = $this->_getConfig()->getResourceUserPrivileges(
                        $this->_resourceType,
                        $role->getConfigNodeName(),
                    );

                    if (!array_key_exists($this->_operation, $privileges)) {
                        continue;
                    }
                }

                $this->allow($rule->getRoleId());
            } else {
                $this->allow($rule->getRoleId(), $rule->getResourceId(), $rule->getPrivilege());
            }
        }
        return $this;
    }

    /**
     * Adds a Role having an identifier unique to the registry
     * OVERRIDE to allow numeric roles identifiers
     *
     * @param int $roleId Role identifier
     * @param Zend_Acl_Role_Interface|string|array $parents
     * @return Zend_Acl Provides a fluent interface
     */
    #[\Override]
    public function addRole($roleId, $parents = null)
    {
        if (!is_numeric($roleId)) {
            throw new Exception('Invalid role identifier');
        }
        return parent::addRole((string) $roleId);
    }
}
