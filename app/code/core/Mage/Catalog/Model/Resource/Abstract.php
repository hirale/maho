<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method int getStoreId()
 * @method bool getUseDataSharing()
 */
abstract class Mage_Catalog_Model_Resource_Abstract extends Mage_Eav_Model_Entity_Abstract
{
    /**
     * Store firstly set attributes to filter selected attributes when used specific store_id
     *
     * @var array
     */
    protected $_attributes   = [];

    /**
     * Redeclare attribute model
     *
     * @return string
     */
    #[\Override]
    protected function _getDefaultAttributeModel()
    {
        return 'catalog/resource_eav_attribute';
    }

    /**
     * Returns default Store ID
     *
     * @return int
     */
    public function getDefaultStoreId()
    {
        return Mage_Catalog_Model_Abstract::DEFAULT_STORE_ID;
    }

    /**
     * Check whether the attribute is Applicable to the object
     *
     * @param Varien_Object $object
     * @param Mage_Catalog_Model_Resource_Eav_Attribute $attribute
     * @return bool
     */
    #[\Override]
    protected function _isApplicableAttribute($object, $attribute)
    {
        $applyTo = $attribute->getApplyTo();
        return count($applyTo) == 0 || in_array($object->getTypeId(), $applyTo);
    }

    /**
     * Check whether attribute instance (attribute, backend, frontend or source) has method and applicable
     *
     * @param Mage_Eav_Model_Entity_Attribute_Abstract|Mage_Eav_Model_Entity_Attribute_Backend_Abstract|Mage_Eav_Model_Entity_Attribute_Frontend_Abstract|Mage_Eav_Model_Entity_Attribute_Source_Abstract $instance
     * @param string $method
     * @param array $args array of arguments
     * @return bool
     */
    #[\Override]
    protected function _isCallableAttributeInstance($instance, $method, $args)
    {
        if ($instance instanceof Mage_Eav_Model_Entity_Attribute_Backend_Abstract
            && ($method == 'beforeSave' || $method = 'afterSave')
        ) {
            $attributeCode = $instance->getAttribute()->getAttributeCode();
            if (isset($args[0]) && $args[0] instanceof Varien_Object && $args[0]->getData($attributeCode) === false) {
                return false;
            }
        }

        return parent::_isCallableAttributeInstance($instance, $method, $args);
    }

    /**
     * Retrieve select object for loading entity attributes values
     * Join attribute store value
     *
     * @param Varien_Object $object
     * @param string $table
     * @return Varien_Db_Select
     */
    #[\Override]
    protected function _getLoadAttributesSelect($object, $table)
    {
        /**
         * This condition is applicable for all cases when we was work in not single
         * store mode, customize some value per specific store view and than back
         * to single store mode. We should load correct values
         */
        if (Mage::app()->isSingleStoreMode()) {
            $storeId = (int) Mage::app()->getStore(true)->getId();
        } else {
            $storeId = (int) $object->getStoreId();
        }

        $setId  = $object->getAttributeSetId();
        $storeIds = [$this->getDefaultStoreId()];
        if ($storeId != $this->getDefaultStoreId()) {
            $storeIds[] = $storeId;
        }

        $select = $this->_getReadAdapter()->select()
            ->from(['attr_table' => $table], [])
            ->where("attr_table.{$this->getEntityIdField()} = ?", $object->getId())
            ->where('attr_table.store_id IN (?)', $storeIds);
        if (count($storeIds) > 1) {
            $select->order('attr_table.store_id ASC');
        }
        if ($setId) {
            $select->join(
                ['set_table' => $this->getTable('eav/entity_attribute')],
                $this->_getReadAdapter()->quoteInto('attr_table.attribute_id = set_table.attribute_id' .
                ' AND set_table.attribute_set_id = ?', $setId),
                [],
            );
        }
        return $select;
    }

    /**
     * Adds Columns prepared for union
     *
     * @param Varien_Db_Select $select
     * @param string $table
     * @param string $type
     * @return Varien_Db_Select
     */
    #[\Override]
    protected function _addLoadAttributesSelectFields($select, $table, $type)
    {
        /** @var Mage_Catalog_Model_Resource_Helper_Mysql4 $helper */
        $helper = Mage::getResourceHelper('catalog');
        $select->columns(
            $helper->attributeSelectFields('attr_table', $type),
        );
        return $select;
    }

    /**
     * Prepare select object for loading entity attributes values
     *
     * @return Varien_Db_Select
     */
    #[\Override]
    protected function _prepareLoadSelect(array $selects)
    {
        $select = parent::_prepareLoadSelect($selects);
        $select->order('store_id');
        return $select;
    }

    /**
     * Initialize attribute value for object
     *
     * @param Mage_Catalog_Model_Abstract $object
     * @param array $valueRow
     * @return Mage_Catalog_Model_Resource_Abstract
     */
    #[\Override]
    protected function _setAttributeValue($object, $valueRow)
    {
        $attribute = $this->getAttribute($valueRow['attribute_id']);
        if ($attribute) {
            $attributeCode = $attribute->getAttributeCode();
            $isDefaultStore = $valueRow['store_id'] == $this->getDefaultStoreId();
            if (isset($this->_attributes[$valueRow['attribute_id']])) {
                if ($isDefaultStore) {
                    $object->setAttributeDefaultValue($attributeCode, $valueRow['value']);
                } else {
                    $object->setAttributeDefaultValue(
                        $attributeCode,
                        $this->_attributes[$valueRow['attribute_id']]['value'],
                    );
                }
            } else {
                $this->_attributes[$valueRow['attribute_id']] = $valueRow;
            }

            $value   = $valueRow['value'];
            $valueId = $valueRow['value_id'];

            $object->setData($attributeCode, $value);
            if (!$isDefaultStore) {
                $object->setExistsStoreValueFlag($attributeCode);
            }
            $attribute->getBackend()->setEntityValueId($object, $valueId);
        }

        return $this;
    }

    /**
     * Insert or Update attribute data
     *
     * @param Mage_Catalog_Model_Abstract|Varien_Object $object
     * @param Mage_Eav_Model_Entity_Attribute_Abstract|Mage_Catalog_Model_Resource_Eav_Attribute $attribute
     * @param mixed $value
     * @return Mage_Catalog_Model_Resource_Abstract
     */
    protected function _saveAttributeValue($object, $attribute, $value)
    {
        $write   = $this->_getWriteAdapter();
        $storeId = (int) Mage::app()->getStore($object->getStoreId())->getId();
        $table   = $attribute->getBackend()->getTable();

        /**
         * If we work in single store mode all values should be saved just
         * for default store id
         * In this case we clear all not default values
         */
        if (Mage::app()->isSingleStoreMode()) {
            $storeId = $this->getDefaultStoreId();
            $write->delete($table, [
                'attribute_id = ?' => $attribute->getAttributeId(),
                'entity_id = ?'    => $object->getEntityId(),
                'store_id <> ?'    => $storeId,
            ]);
        }

        $data = new Varien_Object([
            'entity_type_id'    => $attribute->getEntityTypeId(),
            'attribute_id'      => $attribute->getAttributeId(),
            'store_id'          => $storeId,
            'entity_id'         => $object->getEntityId(),
            'value'             => $this->_prepareValueForSave($value, $attribute),
        ]);
        $bind = $this->_prepareDataForTable($data, $table);

        if ($attribute->isScopeStore()) {
            /**
             * Update attribute value for store
             */
            $this->_attributeValuesToSave[$table][] = $bind;
        } elseif ($attribute->isScopeWebsite() && $storeId != $this->getDefaultStoreId()) {
            /**
             * Update attribute value for website
             */
            $storeIds = Mage::app()->getStore($storeId)->getWebsite()->getStoreIds(true);
            foreach ($storeIds as $storeId) {
                $bind['store_id'] = (int) $storeId;
                $this->_attributeValuesToSave[$table][] = $bind;
            }
        } else {
            /**
             * Update global attribute value
             */
            $bind['store_id'] = $this->getDefaultStoreId();
            $this->_attributeValuesToSave[$table][] = $bind;
        }

        return $this;
    }

    /**
     * Insert entity attribute value
     *
     * @param Varien_Object $object
     * @param Mage_Eav_Model_Entity_Attribute_Abstract $attribute
     * @param mixed $value
     * @return Mage_Catalog_Model_Resource_Abstract
     */
    #[\Override]
    protected function _insertAttribute($object, $attribute, $value)
    {
        /**
         * save required attributes in global scope every time if store id different from default
         */
        $storeId = (int) Mage::app()->getStore($object->getStoreId())->getId();
        if ($attribute->getIsRequired() && $this->getDefaultStoreId() != $storeId) {
            $table = $attribute->getBackend()->getTable();

            $select = $this->_getReadAdapter()->select()
                ->from($table)
                ->where('entity_type_id = ?', $attribute->getEntityTypeId())
                ->where('attribute_id = ?', $attribute->getAttributeId())
                ->where('store_id = ?', $this->getDefaultStoreId())
                ->where('entity_id = ?', $object->getEntityId());
            $row = $this->_getReadAdapter()->fetchOne($select);

            if (!$row) {
                $data  = new Varien_Object([
                    'entity_type_id'    => $attribute->getEntityTypeId(),
                    'attribute_id'      => $attribute->getAttributeId(),
                    'store_id'          => $this->getDefaultStoreId(),
                    'entity_id'         => $object->getEntityId(),
                    'value'             => $this->_prepareValueForSave($value, $attribute),
                ]);
                $bind  = $this->_prepareDataForTable($data, $table);
                $this->_getWriteAdapter()->insertOnDuplicate($table, $bind, ['value']);
            }
        }

        return $this->_saveAttributeValue($object, $attribute, $value);
    }

    /**
     * Update entity attribute value
     *
     * @deprecated after 1.5.1.0
     * @see Mage_Catalog_Model_Resource_Abstract::_saveAttributeValue()
     *
     * @param Varien_Object $object
     * @param Mage_Eav_Model_Entity_Attribute_Abstract $attribute
     * @param mixed $valueId
     * @param mixed $value
     * @return Mage_Catalog_Model_Resource_Abstract
     */
    #[\Override]
    protected function _updateAttribute($object, $attribute, $valueId, $value)
    {
        return $this->_saveAttributeValue($object, $attribute, $value);
    }

    /**
     * Update attribute value for specific store
     *
     * @param Mage_Catalog_Model_Abstract $object
     * @param object $attribute
     * @param mixed $value
     * @param int $storeId
     * @return Mage_Catalog_Model_Resource_Abstract
     */
    protected function _updateAttributeForStore($object, $attribute, $value, $storeId)
    {
        $adapter = $this->_getWriteAdapter();
        $table   = $attribute->getBackend()->getTable();
        $entityIdField = $attribute->getBackend()->getEntityIdField();
        $select  = $adapter->select()
            ->from($table, 'value_id')
            ->where('entity_type_id = :entity_type_id')
            ->where("$entityIdField = :entity_field_id")
            ->where('store_id = :store_id')
            ->where('attribute_id = :attribute_id');
        $bind = [
            'entity_type_id'  => $object->getEntityTypeId(),
            'entity_field_id' => $object->getId(),
            'store_id'        => $storeId,
            'attribute_id'    => $attribute->getId(),
        ];
        $valueId = $adapter->fetchOne($select, $bind);
        /**
         * When value for store exist
         */
        if ($valueId) {
            $bind  = ['value' => $this->_prepareValueForSave($value, $attribute)];
            $where = ['value_id = ?' => (int) $valueId];

            $adapter->update($table, $bind, $where);
        } else {
            $bind  = [
                'entity_field_id'   => (int) $object->getId(),
                'entity_type_id'    => (int) $object->getEntityTypeId(),
                'attribute_id'      => (int) $attribute->getId(),
                'value'             => $this->_prepareValueForSave($value, $attribute),
                'store_id'          => (int) $storeId,
            ];

            $adapter->insert($table, $bind);
        }

        return $this;
    }

    /**
     * Delete entity attribute values
     *
     * @param Varien_Object $object
     * @param string $table
     * @param array $info
     * @return Mage_Catalog_Model_Resource_Abstract
     */
    #[\Override]
    protected function _deleteAttributes($object, $table, $info)
    {
        $adapter            = $this->_getWriteAdapter();
        $entityIdField      = $this->getEntityIdField();
        $globalValues       = [];
        $websiteAttributes  = [];
        $storeAttributes    = [];

        /**
         * Separate attributes by scope
         */
        foreach ($info as $itemData) {
            $attribute = $this->getAttribute($itemData['attribute_id']);
            if ($attribute->isScopeStore()) {
                $storeAttributes[] = (int) $itemData['attribute_id'];
            } elseif ($attribute->isScopeWebsite()) {
                $websiteAttributes[] = (int) $itemData['attribute_id'];
            } else {
                $globalValues[] = (int) $itemData['value_id'];
            }
        }

        /**
         * Delete global scope attributes
         */
        if (!empty($globalValues)) {
            $adapter->delete($table, ['value_id IN (?)' => $globalValues]);
        }

        $condition = [
            $entityIdField . ' = ?' => $object->getId(),
            'entity_type_id = ?'  => $object->getEntityTypeId(),
        ];

        /**
         * Delete website scope attributes
         */
        if (!empty($websiteAttributes)) {
            $storeIds = $object->getWebsiteStoreIds();
            if (!empty($storeIds)) {
                $delCondition = $condition;
                $delCondition['attribute_id IN(?)'] = $websiteAttributes;
                $delCondition['store_id IN(?)'] = $storeIds;

                $adapter->delete($table, $delCondition);
            }
        }

        /**
         * Delete store scope attributes
         */
        if (!empty($storeAttributes)) {
            $delCondition = $condition;
            $delCondition['attribute_id IN(?)'] = $storeAttributes;
            $delCondition['store_id = ?']       = (int) $object->getStoreId();

            $adapter->delete($table, $delCondition);
        }

        return $this;
    }

    /**
     * Retrieve Object instance with original data
     *
     * @param Varien_Object $object
     * @return Varien_Object
     */
    #[\Override]
    protected function _getOrigObject($object)
    {
        $className  = $object::class;
        $origObject = new $className();
        $origObject->setData([]);
        $origObject->setStoreId($object->getStoreId());
        $this->load($origObject, $object->getData($this->getEntityIdField()));

        return $origObject;
    }

    /**
     * Collect original data
     *
     * @deprecated after 1.5.1.0
     *
     * @param Varien_Object $object
     * @return array
     */
    protected function _collectOrigData($object)
    {
        $this->loadAllAttributes($object);

        if ($this->getUseDataSharing()) {
            $storeId = $object->getStoreId();
        } else {
            $storeId = $this->getStoreId();
        }

        $data = [];
        foreach ($this->getAttributesByTable() as $table => $attributes) {
            $select = $this->_getReadAdapter()->select()
                ->from($table)
                ->where($this->getEntityIdField() . '=?', $object->getId());

            $where = $this->_getReadAdapter()->quoteInto('store_id=?', $storeId);

            $globalAttributeIds = [];
            foreach ($attributes as $attr) {
                if ($attr->getIsGlobal()) {
                    $globalAttributeIds[] = $attr->getId();
                }
            }
            if (!empty($globalAttributeIds)) {
                $where .= ' or ' . $this->_getReadAdapter()->quoteInto('attribute_id in (?)', $globalAttributeIds);
            }
            $select->where($where);

            $values = $this->_getReadAdapter()->fetchAll($select);

            if (empty($values)) {
                continue;
            }

            foreach ($values as $row) {
                $data[$this->getAttribute($row['attribute_id'])->getName()][$row['store_id']] = $row;
            }
        }
        return $data;
    }

    /**
     * Check is attribute value empty
     *
     * @param mixed $value
     * @return bool
     */
    #[\Override]
    protected function _isAttributeValueEmpty(Mage_Eav_Model_Entity_Attribute_Abstract $attribute, $value)
    {
        return $value === false;
    }

    /**
     * Return if attribute exists in original data array.
     * Checks also attribute's store scope:
     * We should insert on duplicate key update values if we unchecked 'STORE VIEW' checkbox in store view.
     *
     * @param mixed $value New value of the attribute.
     * @return bool
     */
    #[\Override]
    protected function _canUpdateAttribute(
        Mage_Eav_Model_Entity_Attribute_Abstract $attribute,
        $value,
        array &$origData,
    ) {
        $result = parent::_canUpdateAttribute($attribute, $value, $origData);
        if ($result &&
            ($attribute->isScopeStore() || $attribute->isScopeWebsite()) &&
            !$this->_isAttributeValueEmpty($attribute, $value) &&
            $value == $origData[$attribute->getAttributeCode()] &&
            isset($origData['store_id']) && $origData['store_id'] != $this->getDefaultStoreId()
        ) {
            return false;
        }

        return $result;
    }

    /**
     * Prepare value for save
     *
     * @param mixed $value
     * @return mixed
     */
    #[\Override]
    protected function _prepareValueForSave($value, Mage_Eav_Model_Entity_Attribute_Abstract $attribute)
    {
        $type = $attribute->getBackendType();
        if (($type === 'int' || $type === 'decimal' || $type === 'datetime') && $value === '') {
            $value = null;
        }

        return parent::_prepareValueForSave($value, $attribute);
    }

    /**
     * Retrieve attribute's raw value from DB.
     *
     * @param int $entityId
     * @param int|string|array $attribute attribute's ids or codes
     * @param int|Mage_Core_Model_Store $store
     * @return bool|string|null|array
     */
    public function getAttributeRawValue($entityId, $attribute, $store)
    {
        if (!$entityId || empty($attribute)) {
            return false;
        }

        $returnArray = false;
        $entityId = (int) $entityId;

        if (!is_array($attribute)) {
            $attribute = [$attribute];
        } elseif (count($attribute) > 1) {
            $returnArray = true;
        }

        $attributesData   = [];
        $staticAttributes = [];
        $typedAttributes  = [];
        $staticTable      = null;
        $adapter          = $this->_getReadAdapter();
        $getPerStore      = false;

        foreach ($attribute as $_attribute) {
            $_attribute = $this->getAttribute($_attribute);
            if (!$_attribute) {
                continue;
            }
            $attributeCode = $_attribute->getAttributeCode();
            $attrTable     = $_attribute->getBackend()->getTable();
            $isStatic      = $_attribute->getBackend()->isStatic();

            if (!$getPerStore && $_attribute->getIsGlobal() != Mage_Catalog_Model_Resource_Eav_Attribute::SCOPE_GLOBAL) {
                $getPerStore = true;
            }

            if ($isStatic) {
                $staticAttributes[] = $attributeCode;
                $staticTable = $attrTable;
            } else {
                /**
                 * That structure needed to avoid farther sql joins for getting attribute's code by id
                 */
                $typedAttributes[$attrTable][$_attribute->getId()] = $attributeCode;
            }
        }

        /**
         * Collecting static attributes
         */
        if ($staticAttributes) {
            $select = $adapter->select()->from($staticTable, $staticAttributes)
                ->where($this->getEntityIdField() . ' = :entity_id');
            $attributesData = $adapter->fetchRow($select, ['entity_id' => $entityId]) ?: [];
        }

        /**
         * Collecting typed attributes, performing separate SQL query for each attribute type table
         */
        if ($typedAttributes) {
            if ($store instanceof Mage_Core_Model_Store) {
                $store = $store->getId();
            }

            $store = (int) $store;

            foreach ($typedAttributes as $table => $attributes) {
                // see also Mage_Catalog_Model_Resource_Collection_Abstract::_getLoadAttributesSelect()
                if ($getPerStore && $store != $this->getDefaultStoreId()) {
                    $select = $adapter->select()
                        ->from(['e' => $this->getEntityTable()], [])
                        ->where('e.entity_id = ?', $entityId);
                    // attr join
                    $select->joinInner(
                        ['attr' => $table],
                        implode(' AND ', [
                            'attr.entity_id = e.entity_id',
                            $adapter->quoteInto('attr.attribute_id IN (?)', array_keys($attributes)),
                            'attr.store_id IN (' . $this->getDefaultStoreId() . ', ' . $store . ')',
                            'attr.entity_type_id = ' . $this->getTypeId(),
                        ]),
                        [],
                    );
                    // default_value join
                    $select->joinLeft(
                        ['default_value' => $table],
                        implode(' AND ', [
                            'default_value.entity_id = e.entity_id',
                            'default_value.attribute_id = attr.attribute_id',
                            'default_value.store_id = ' . $this->getDefaultStoreId(),
                        ]),
                        [],
                    );
                    // store_value join
                    $valueExpr = $adapter->getCheckSql(
                        'store_value.attribute_id IS NULL',
                        'default_value.value',
                        'store_value.value',
                    );
                    $attributeIdExpr = $adapter->getCheckSql(
                        'store_value.attribute_id IS NULL',
                        'default_value.attribute_id',
                        'store_value.attribute_id',
                    );
                    $select->joinLeft(
                        ['store_value' => $table],
                        implode(' AND ', [
                            'store_value.entity_id = e.entity_id',
                            'store_value.attribute_id = attr.attribute_id',
                            'store_value.store_id = ' . $store,
                        ]),
                        ['attribute_id' => $attributeIdExpr, 'attr_value' => $valueExpr],
                    );
                    $select->group('attr.attribute_id');
                } else {
                    $select = $adapter->select()
                        ->from(['default_value' => $table], ['attribute_id', 'attr_value' => 'value'])
                        ->where('default_value.entity_id = ?', $entityId)
                        ->where('default_value.attribute_id IN (?)', array_keys($attributes))
                        ->where('default_value.store_id = ?', $this->getDefaultStoreId())
                        ->where('default_value.entity_type_id = ?', $this->getTypeId());
                }

                $result = $adapter->fetchPairs($select);
                foreach ($result as $attrId => $value) {
                    if (!empty($attrId)) {
                        $attrCode = $typedAttributes[$table][$attrId];
                        $attributesData[$attrCode] = $value;
                    }
                }
            }
        }

        if (count($attributesData) === 1 && !$returnArray) {
            return reset($attributesData);
        }

        return $attributesData ?: false;
    }

    /**
     * Retrieve attribute's raw value from DB using its source model if available.
     *
     * @param int $entityId
     * @param int|string|array $attribute attribute's ids or codes
     * @param int|Mage_Core_Model_Store $store
     * @return bool|string|array
     */
    public function getAttributeRawText($entityId, $attribute, $store)
    {
        if (!$entityId || empty($attribute)) {
            return false;
        }

        if ($store instanceof Mage_Core_Model_Store) {
            $store = $store->getId();
        }

        $store = (int) $store;
        $attribute = is_array($attribute) ? $attribute : [$attribute];
        $value = $this->getAttributeRawValue($entityId, $attribute, $store);

        if (!$value) {
            return false;
        }

        // Ensure we have an associative array of attribute => values
        $values = is_array($value) ? $value : array_combine($attribute, [$value]);

        foreach ($values as $_attribute => &$optionText) {
            $_attribute = (clone $this->getAttribute($_attribute))->setStoreId($store);
            if ($_attribute->getSourceModel() || $_attribute->getFrontendInput() === 'select' || $_attribute->getFrontendInput() === 'multiselect') {
                $optionText = $_attribute->getSource()->getOptionText($optionText);
            }
        }

        return count($values) === 1 ? reset($values) : $values;
    }

    /**
     * Reset firstly loaded attributes
     */
    #[\Override]
    public function load($object, $entityId, $attributes = [])
    {
        $this->_attributes = [];
        return parent::load($object, $entityId, $attributes);
    }
}
