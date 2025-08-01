<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2018-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Catalog_Model_Resource_Category extends Mage_Catalog_Model_Resource_Abstract
{
    /**
     * Category tree object
     *
     * @var Mage_Catalog_Model_Resource_Category_Tree
     */
    protected $_tree;

    /**
     * Catalog products table name
     *
     * @var string
     */
    protected $_categoryProductTable;

    /**
     * Id of 'is_active' category attribute
     *
     * @var int
     */
    protected $_isActiveAttributeId      = null;

    /**
     * Store id
     *
     * @var int
     */
    protected $_storeId                  = null;

    /**
     * Class constructor
     *
     */
    public function __construct()
    {
        $resource = Mage::getSingleton('core/resource');
        $this->setType(Mage_Catalog_Model_Category::ENTITY)
            ->setConnection(
                $resource->getConnection('catalog_read'),
                $resource->getConnection('catalog_write'),
            );
        $this->_categoryProductTable = $this->getTable('catalog/category_product');
    }

    /**
     * Set store Id
     *
     * @param int $storeId
     * @return $this
     */
    public function setStoreId($storeId)
    {
        $this->_storeId = $storeId;
        return $this;
    }

    /**
     * Return store id
     *
     * @return int
     */
    public function getStoreId()
    {
        return $this->_storeId ?? Mage::app()->getStore()->getId();
    }

    /**
     * Retrieve category tree object
     *
     * @return Mage_Catalog_Model_Resource_Category_Tree
     */
    protected function _getTree()
    {
        if (!$this->_tree) {
            $this->_tree = Mage::getResourceModel('catalog/category_tree')
                ->load();
        }
        return $this->_tree;
    }

    /**
     * Process category data before delete
     * update children count for parent category
     * delete child categories
     *
     * @return $this
     */
    #[\Override]
    protected function _beforeDelete(Varien_Object $object)
    {
        parent::_beforeDelete($object);

        /**
         * Update children count for all parent categories
         */
        $parentIds = $object->getParentIds();
        if ($parentIds) {
            $childDecrease = $object->getChildrenCount() + 1; // +1 is itself
            $data = ['children_count' => new Zend_Db_Expr('children_count - ' . $childDecrease)];
            $where = ['entity_id IN(?)' => $parentIds];
            $this->_getWriteAdapter()->update($this->getEntityTable(), $data, $where);
        }
        $this->deleteChildren($object);
        return $this;
    }

    /**
     * Delete children categories of specific category
     *
     * @return $this
     */
    public function deleteChildren(Varien_Object $object)
    {
        $adapter = $this->_getWriteAdapter();
        $pathField = $adapter->quoteIdentifier('path');

        $select = $adapter->select()
            ->from($this->getEntityTable(), ['entity_id'])
            ->where($pathField . ' LIKE :c_path');

        $childrenIds = $adapter->fetchCol($select, ['c_path' => $object->getPath() . '/%']);

        if (!empty($childrenIds)) {
            $adapter->delete(
                $this->getEntityTable(),
                ['entity_id IN (?)' => $childrenIds],
            );
        }

        /**
         * Add deleted children ids to object
         * This data can be used in after delete event
         */
        $object->setDeletedChildrenIds($childrenIds);
        return $this;
    }

    /**
     * Process category data before saving
     * prepare path and increment children count for parent categories
     *
     * @return $this
     */
    #[\Override]
    protected function _beforeSave(Varien_Object $object)
    {
        parent::_beforeSave($object);

        if (!$object->getChildrenCount()) {
            $object->setChildrenCount(0);
        }
        if ($object->getLevel() === null) {
            $object->setLevel(1);
        }

        if (!$object->getId()) {
            $object->setPosition($this->_getMaxPosition($object->getPath()) + 1);
            $path  = explode('/', $object->getPath());
            $level = count($path);
            $object->setLevel($level);
            if ($level) {
                $object->setParentId($path[$level - 1]);
            }
            $object->setPath($object->getPath() . '/');

            $toUpdateChild = explode('/', $object->getPath());

            $this->_getWriteAdapter()->update(
                $this->getEntityTable(),
                ['children_count'  => new Zend_Db_Expr('children_count+1')],
                ['entity_id IN(?)' => $toUpdateChild],
            );
        }
        return $this;
    }

    /**
     * Process category data after save category object
     * save related products ids and update path value
     *
     * @param Mage_Catalog_Model_Category $object
     */
    #[\Override]
    protected function _afterSave(Varien_Object $object)
    {
        /**
         * Add identifier for new category
         */
        if (str_ends_with($object->getPath(), '/')) {
            $object->setPath($object->getPath() . $object->getId());
            $this->_savePath($object);
        }

        $this->_saveCategoryProducts($object);

        // Save dynamic rule data if present
        if ($object->getDynamicRuleData()) {
            $this->_saveDynamicRule($object);
        }

        return parent::_afterSave($object);
    }

    /**
     * Update path field
     *
     * @param Mage_Catalog_Model_Category $object
     * @return $this
     */
    protected function _savePath($object)
    {
        if ($object->getId()) {
            $this->_getWriteAdapter()->update(
                $this->getEntityTable(),
                ['path' => $object->getPath()],
                ['entity_id = ?' => $object->getId()],
            );
        }
        return $this;
    }

    /**
     * Get maximum position of child categories by specific tree path
     *
     * @param string $path
     * @return int
     */
    protected function _getMaxPosition($path)
    {
        $adapter = $this->getReadConnection();
        $positionField = $adapter->quoteIdentifier('position');
        $level   = count(explode('/', $path));
        $bind = [
            'c_level' => $level,
            'c_path'  => $path . '/%',
        ];
        $select  = $adapter->select()
            ->from($this->getTable('catalog/category'), 'MAX(' . $positionField . ')')
            ->where($adapter->quoteIdentifier('path') . ' LIKE :c_path')
            ->where($adapter->quoteIdentifier('level') . ' = :c_level');

        $position = $adapter->fetchOne($select, $bind);
        if (!$position) {
            $position = 0;
        }
        return $position;
    }

    /**
     * Save category products relation
     *
     * @param Mage_Catalog_Model_Category $category
     * @return $this
     */
    protected function _saveCategoryProducts($category)
    {
        $category->setIsChangedProductList(false);
        $id = $category->getId();
        /**
         * new category-product relationships
         */
        $products = $category->getPostedProducts();

        /**
         * Example re-save category
         */
        if ($products === null) {
            return $this;
        }

        /**
         * old category-product relationships
         */
        $oldProducts = $category->getProductsPosition();

        $insert = array_diff_key($products, $oldProducts);
        $delete = array_diff_key($oldProducts, $products);

        /**
         * Find product ids which are presented in both arrays
         * and saved before (check $oldProducts array)
         */
        $update = array_intersect_key($products, $oldProducts);
        $update = array_diff_assoc($update, $oldProducts);

        $adapter = $this->_getWriteAdapter();

        /**
         * Delete products from category
         */
        if (!empty($delete)) {
            $cond = [
                'product_id IN(?)' => array_keys($delete),
                'category_id=?' => $id,
            ];
            $adapter->delete($this->_categoryProductTable, $cond);
        }

        /**
         * Add products to category
         */
        if (!empty($insert)) {
            $data = [];
            foreach ($insert as $productId => $position) {
                $data[] = [
                    'category_id' => (int) $id,
                    'product_id'  => (int) $productId,
                    'position'    => (int) $position,
                ];
            }
            $adapter->insertMultiple($this->_categoryProductTable, $data);
        }

        /**
         * Update product positions in category
         */
        if (!empty($update)) {
            foreach ($update as $productId => $position) {
                $where = [
                    'category_id = ?' => (int) $id,
                    'product_id = ?' => (int) $productId,
                ];
                $bind  = ['position' => (int) $position];
                $adapter->update($this->_categoryProductTable, $bind, $where);
            }
        }

        if (!empty($insert) || !empty($delete)) {
            $productIds = array_unique(array_merge(array_keys($insert), array_keys($delete)));
            Mage::dispatchEvent('catalog_category_change_products', [
                'category'      => $category,
                'product_ids'   => $productIds,
            ]);
        }

        if (!empty($insert) || !empty($update) || !empty($delete)) {
            $category->setIsChangedProductList(true);

            /**
             * Setting affected products to category for third party engine index refresh
             */
            $productIds = array_keys($insert + $delete + $update);
            $category->setAffectedProductIds($productIds);
        }
        return $this;
    }

    /**
     * Get positions of associated to category products
     *
     * @param Mage_Catalog_Model_Category $category
     * @return array
     */
    public function getProductsPosition($category)
    {
        $select = $this->_getWriteAdapter()->select()
            ->from($this->_categoryProductTable, ['product_id', 'position'])
            ->where('category_id = :category_id');
        $bind = ['category_id' => (int) $category->getId()];

        return $this->_getWriteAdapter()->fetchPairs($select, $bind);
    }

    /**
     * Get children categories count
     *
     * @param int $categoryId
     * @return string
     */
    public function getChildrenCount($categoryId)
    {
        $select = $this->_getReadAdapter()->select()
            ->from($this->getEntityTable(), 'children_count')
            ->where('entity_id = :entity_id');
        $bind = ['entity_id' => $categoryId];

        return $this->_getReadAdapter()->fetchOne($select, $bind);
    }

    /**
     * Check if category id exist
     *
     * @param int $entityId
     * @return string
     */
    public function checkId($entityId)
    {
        $select = $this->_getReadAdapter()->select()
            ->from($this->getEntityTable(), 'entity_id')
            ->where('entity_id = :entity_id');
        $bind =  ['entity_id' => $entityId];

        return $this->_getReadAdapter()->fetchOne($select, $bind);
    }

    /**
     * Check array of category identifiers
     *
     * @return array
     */
    public function verifyIds(array $ids)
    {
        if (empty($ids)) {
            return [];
        }

        $select = $this->_getReadAdapter()->select()
            ->from($this->getEntityTable(), 'entity_id')
            ->where('entity_id IN(?)', $ids);

        return $this->_getReadAdapter()->fetchCol($select);
    }

    /**
     * Get count of active/not active children categories
     *
     * @param Mage_Catalog_Model_Category $category
     * @param bool $isActiveFlag
     * @return string
     */
    public function getChildrenAmount($category, $isActiveFlag = true)
    {
        $storeId = Mage::app()->getStore()->getId();
        $attributeId = $this->_getIsActiveAttributeId();
        $table   = $this->getTable([$this->getEntityTablePrefix(), 'int']);
        $adapter = $this->_getReadAdapter();
        $checkSql = $adapter->getCheckSql('c.value_id > 0', 'c.value', 'd.value');

        $bind = [
            'attribute_id' => $attributeId,
            'store_id'     => $storeId,
            'active_flag'  => $isActiveFlag,
            'c_path'       => $category->getPath() . '/%',
        ];
        $select = $adapter->select()
            ->from(['m' => $this->getEntityTable()], ['COUNT(m.entity_id)'])
            ->joinLeft(
                ['d' => $table],
                'd.attribute_id = :attribute_id AND d.store_id = 0 AND d.entity_id = m.entity_id',
                [],
            )
            ->joinLeft(
                ['c' => $table],
                'c.attribute_id = :attribute_id AND c.store_id = :store_id AND c.entity_id = m.entity_id',
                [],
            )
            ->where('m.path LIKE :c_path')
            ->where($checkSql . ' = :active_flag');

        return $this->_getReadAdapter()->fetchOne($select, $bind);
    }

    /**
     * Get "is_active" attribute identifier
     *
     * @return int
     */
    protected function _getIsActiveAttributeId()
    {
        if ($this->_isActiveAttributeId === null) {
            $attributeId = Mage::getSingleton('eav/config')
                ->getAttribute(Mage_Catalog_Model_Category::ENTITY, 'is_active')
                ->getId();
            if (!is_int($attributeId)) {
                Mage::throwException('Failed to find category attribute is_active');
            }
            $this->_isActiveAttributeId = $attributeId;
        }

        return $this->_isActiveAttributeId;
    }

    /**
     * Return entities where attribute value is
     *
     * @param array|int $entityIdsFilter
     * @param Mage_Eav_Model_Entity_Attribute $attribute
     * @param mixed $expectedValue
     * @return array
     */
    public function findWhereAttributeIs($entityIdsFilter, $attribute, $expectedValue)
    {
        $bind = [
            'attribute_id' => $attribute->getId(),
            'value'        => $expectedValue,
        ];
        $select = $this->_getReadAdapter()->select()
            ->from($attribute->getBackend()->getTable(), ['entity_id'])
            ->where('attribute_id = :attribute_id')
            ->where('value = :value')
            ->where('entity_id IN(?)', $entityIdsFilter);

        return $this->_getReadAdapter()->fetchCol($select, $bind);
    }

    /**
     * Get products count in category
     *
     * @param Mage_Catalog_Model_Category $category
     * @return int
     */
    public function getProductCount($category)
    {
        $productTable = Mage::getSingleton('core/resource')->getTableName('catalog/category_product');

        $select = $this->getReadConnection()->select()
            ->from(
                ['main_table' => $productTable],
                [new Zend_Db_Expr('COUNT(main_table.product_id)')],
            )
            ->where('main_table.category_id = :category_id');

        $bind = ['category_id' => (int) $category->getId()];
        $counts = $this->getReadConnection()->fetchOne($select, $bind);

        return (int) $counts;
    }

    /**
     * Retrieve categories
     *
     * @param int $parent
     * @param int $recursionLevel
     * @param bool|string $sorted
     * @param bool $asCollection
     * @param bool $toLoad
     * @return Varien_Data_Tree_Node_Collection|Mage_Catalog_Model_Resource_Category_Collection
     */
    public function getCategories($parent, $recursionLevel = 0, $sorted = false, $asCollection = false, $toLoad = true)
    {
        $tree = Mage::getResourceModel('catalog/category_tree');
        /** @var Mage_Catalog_Model_Resource_Category_Tree $tree */
        $nodes = $tree->loadNode($parent)
            ->loadChildren($recursionLevel)
            ->getChildren();

        $tree->addCollectionData(null, $sorted, $parent, $toLoad, true);

        if ($asCollection) {
            return $tree->getCollection();
        }
        return $nodes;
    }

    /**
     * Return parent categories of category
     *
     * @param Mage_Catalog_Model_Category $category
     * @return Mage_Catalog_Model_Category[]
     */
    public function getParentCategories($category)
    {
        $pathIds = array_reverse(explode(',', $category->getPathInStore()));
        return Mage::getResourceModel('catalog/category_collection')
            ->setStore(Mage::app()->getStore())
            ->addAttributeToSelect('name')
            ->addAttributeToSelect('url_key')
            ->addFieldToFilter('entity_id', ['in' => $pathIds])
            ->addFieldToFilter('is_active', 1)
            ->load()
            ->getItems();
    }

    /**
     * Return parent category of current category with own custom design settings
     *
     * @param Mage_Catalog_Model_Category $category
     * @return Mage_Catalog_Model_Category
     */
    public function getParentDesignCategory($category)
    {
        $pathIds = array_reverse($category->getPathIds());
        $collection = $category->getCollection()
            ->setStore(Mage::app()->getStore())
            ->addAttributeToSelect('custom_design')
            ->addAttributeToSelect('custom_design_from')
            ->addAttributeToSelect('custom_design_to')
            ->addAttributeToSelect('page_layout')
            ->addAttributeToSelect('custom_layout_update')
            ->addAttributeToSelect('custom_apply_to_products')
            ->addFieldToFilter('entity_id', ['in' => $pathIds])
            ->addAttributeToFilter('custom_use_parent_settings', [['eq' => 0], ['null' => 0]], 'left')
            ->addFieldToFilter('level', ['neq' => 0])
            ->setOrder('level', 'DESC')
            ->load();
        return $collection->getFirstItem();
    }

    /**
     * Prepare base collection setup for get categories list
     *
     * @param Mage_Catalog_Model_Category $category
     * @return Mage_Catalog_Model_Resource_Category_Collection
     */
    protected function _getChildrenCategoriesBase($category)
    {
        $collection = $category->getCollection();
        $collection->addAttributeToSelect('url_key')
            ->addAttributeToSelect('name')
            ->addAttributeToSelect('all_children')
            ->addAttributeToSelect('is_anchor')
            ->setOrder('position', Varien_Db_Select::SQL_ASC)
            ->joinUrlRewrite();

        return $collection;
    }

    /**
     * Return child categories
     *
     * @param Mage_Catalog_Model_Category $category
     * @return Mage_Catalog_Model_Resource_Category_Collection
     */
    public function getChildrenCategories($category)
    {
        $collection = $this->_getChildrenCategoriesBase($category);
        $collection->addAttributeToFilter('is_active', 1)
            ->addIdFilter($category->getChildren())
            ->load();

        return $collection;
    }

    /**
     * Return children categories lists with inactive
     *
     * @param Mage_Catalog_Model_Category $category
     * @return Mage_Catalog_Model_Resource_Category_Collection
     */
    public function getChildrenCategoriesWithInactive($category)
    {
        $collection = $this->_getChildrenCategoriesBase($category);
        $collection->addFieldToFilter('parent_id', $category->getId());

        return $collection;
    }

    /**
     * Returns select for category's children.
     *
     * @param Mage_Catalog_Model_Category $category
     * @param bool $recursive
     * @return Varien_Db_Select
     */
    protected function _getChildrenIdSelect($category, $recursive = true)
    {
        $adapter = $this->_getReadAdapter();
        $select = $adapter->select()
            ->from(['m' => $this->getEntityTable()], 'entity_id')
            ->where($adapter->quoteIdentifier('path') . ' LIKE ?', $category->getPath() . '/%');

        if (!$recursive) {
            $select->where($adapter->quoteIdentifier('level') . ' <= ?', $category->getLevel() + 1);
        }
        return $select;
    }

    /**
     * Return children ids of category
     *
     * @param Mage_Catalog_Model_Category $category
     * @param bool $recursive
     * @return array
     */
    public function getChildren($category, $recursive = true)
    {
        $attributeId  = (int) $this->_getIsActiveAttributeId();
        $backendTable = $this->getTable([$this->getEntityTablePrefix(), 'int']);
        $adapter      = $this->_getReadAdapter();
        $checkSql     = $adapter->getCheckSql('c.value_id > 0', 'c.value', 'd.value');
        $bind = [
            'attribute_id' => $attributeId,
            'store_id'     => $category->getStoreId(),
            'scope'        => 1,
        ];
        $select = $this->_getChildrenIdSelect($category, $recursive);
        $select
            ->joinLeft(
                ['d' => $backendTable],
                'd.attribute_id = :attribute_id AND d.store_id = 0 AND d.entity_id = m.entity_id',
                [],
            )
            ->joinLeft(
                ['c' => $backendTable],
                'c.attribute_id = :attribute_id AND c.store_id = :store_id AND c.entity_id = m.entity_id',
                [],
            )
            ->where($checkSql . ' = :scope')
            ->order('m.position ASC');

        return $adapter->fetchCol($select, $bind);
    }

    /**
     * Return IDs of category's children along with inactive categories.
     *
     * @param Mage_Catalog_Model_Category $category
     * @param bool $recursive
     * @return array
     */
    public function getChildrenIds($category, $recursive = true)
    {
        $select = $this->_getChildrenIdSelect($category, $recursive);
        return $this->_getReadAdapter()->fetchCol($select);
    }

    /**
     * Return all children ids of category (with category id)
     *
     * @param Mage_Catalog_Model_Category $category
     * @return array
     */
    public function getAllChildren($category)
    {
        $children = $this->getChildren($category);
        $myId = [$category->getId()];
        $children = array_merge($myId, $children);

        return $children;
    }

    /**
     * Check if category is a child of current store root category
     *
     * @param Mage_Catalog_Model_Category $category
     * @return bool
     */
    public function isInRootCategoryList($category)
    {
        return $this->isInStoreRootCategory($category);
    }

    /**
     * Check if category is a child of specific store root category
     *
     * @param Mage_Catalog_Model_Category $category
     * @param null|string|bool|int|Mage_Core_Model_Store $store
     */
    public function isInStoreRootCategory($category, $store = null): bool
    {
        $rootCategoryId = Mage::app()->getStore($store)->getRootCategoryId();
        return in_array($rootCategoryId, $category->getParentIds());
    }

    /**
     * Check if category is a child of specific store root category, or the root category itself
     *
     * @param Mage_Catalog_Model_Category $category
     * @param null|string|bool|int|Mage_Core_Model_Store $store
     */
    public function isInStore($category, $store = null): bool
    {
        $rootCategoryId = Mage::app()->getStore($store)->getRootCategoryId();
        return in_array($rootCategoryId, $category->getPathIds());
    }

    /**
     * Return ids of root categories as array
     *
     * @return list<int>
     */
    public function getRootIds(): array
    {
        return array_map(
            fn($store) => (int) $store->getRootCategoryId(),
            Mage::app()->getGroups(),
        );
    }

    /**
     * Check category is forbidden to delete.
     * If category is root and assigned to store group return false
     *
     * @param int $categoryId
     * @return bool
     */
    public function isForbiddenToDelete($categoryId)
    {
        $select = $this->_getReadAdapter()->select()
            ->from($this->getTable('core/store_group'), ['group_id'])
            ->where('root_category_id = :root_category_id');
        $result = $this->_getReadAdapter()->fetchOne($select, ['root_category_id' => $categoryId]);

        if ($result) {
            return true;
        }
        return false;
    }

    /**
     * Get category path value by its id
     *
     * @param int $categoryId
     * @return string
     */
    public function getCategoryPathById($categoryId)
    {
        $select = $this->getReadConnection()->select()
            ->from($this->getEntityTable(), ['path'])
            ->where('entity_id = :entity_id');
        $bind = ['entity_id' => (int) $categoryId];

        return $this->getReadConnection()->fetchOne($select, $bind);
    }

    /**
     * Move category to another parent node
     *
     * @param null|int $afterCategoryId
     * @return $this
     */
    public function changeParent(
        Mage_Catalog_Model_Category $category,
        Mage_Catalog_Model_Category $newParent,
        $afterCategoryId = null,
    ) {
        $childrenCount  = (int) $this->getChildrenCount($category->getId()) + 1;
        $table          = $this->getEntityTable();
        $adapter        = $this->_getWriteAdapter();
        $levelFiled     = $adapter->quoteIdentifier('level');
        $pathField      = $adapter->quoteIdentifier('path');

        /**
         * Decrease children count for all old category parent categories
         */
        $adapter->update(
            $table,
            ['children_count' => new Zend_Db_Expr('children_count - ' . $childrenCount)],
            ['entity_id IN(?)' => $category->getParentIds()],
        );

        /**
         * Increase children count for new category parents
         */
        $adapter->update(
            $table,
            ['children_count' => new Zend_Db_Expr('children_count + ' . $childrenCount)],
            ['entity_id IN(?)' => $newParent->getPathIds()],
        );

        $position = $this->_processPositions($category, $newParent, $afterCategoryId);

        $newPath          = sprintf('%s/%s', $newParent->getPath(), $category->getId());
        $newLevel         = $newParent->getLevel() + 1;
        $levelDisposition = $newLevel - $category->getLevel();

        /**
         * Update children nodes path
         */
        $adapter->update(
            $table,
            [
                'path' => new Zend_Db_Expr('REPLACE(' . $pathField . ',' .
                    $adapter->quote($category->getPath() . '/') . ', ' . $adapter->quote($newPath . '/') . ')'),
                'level' => new Zend_Db_Expr($levelFiled . ' + ' . $levelDisposition),
            ],
            [$pathField . ' LIKE ?' => $category->getPath() . '/%'],
        );
        /**
         * Update moved category data
         */
        $data = [
            'path'      => $newPath,
            'level'     => $newLevel,
            'position'  => $position,
            'parent_id' => $newParent->getId(),
        ];
        $adapter->update($table, $data, ['entity_id = ?' => $category->getId()]);

        // Update category object to new data
        $category->addData($data);

        return $this;
    }

    /**
     * Process positions of old parent category children and new parent category children.
     * Get position for moved category
     *
     * @param Mage_Catalog_Model_Category $category
     * @param Mage_Catalog_Model_Category $newParent
     * @param null|int $afterCategoryId
     * @return int
     */
    protected function _processPositions($category, $newParent, $afterCategoryId)
    {
        $table          = $this->getEntityTable();
        $adapter        = $this->_getWriteAdapter();
        $positionField  = $adapter->quoteIdentifier('position');

        $bind = [
            'position' => new Zend_Db_Expr($positionField . ' - 1'),
        ];
        $where = [
            'parent_id = ?'         => $category->getParentId(),
            $positionField . ' > ?' => $category->getPosition(),
        ];
        $adapter->update($table, $bind, $where);

        /**
         * Prepare position value
         */
        if ($afterCategoryId) {
            $select = $adapter->select()
                ->from($table, 'position')
                ->where('entity_id = :entity_id');
            $position = $adapter->fetchOne($select, ['entity_id' => $afterCategoryId]);

            $bind = [
                'position' => new Zend_Db_Expr($positionField . ' + 1'),
            ];
            $where = [
                'parent_id = ?' => $newParent->getId(),
                $positionField . ' > ?' => $position,
            ];
            $adapter->update($table, $bind, $where);
        } elseif ($afterCategoryId !== null) {
            $position = 0;
            $bind = [
                'position' => new Zend_Db_Expr($positionField . ' + 1'),
            ];
            $where = [
                'parent_id = ?' => $newParent->getId(),
                $positionField . ' > ?' => $position,
            ];
            $adapter->update($table, $bind, $where);
        } else {
            $select = $adapter->select()
                ->from($table, ['position' => new Zend_Db_Expr('MIN(' . $positionField . ')')])
                ->where('parent_id = :parent_id');
            $position = $adapter->fetchOne($select, ['parent_id' => $newParent->getId()]);
        }
        ++$position;

        return $position;
    }

    protected function _saveDynamicRule(Mage_Catalog_Model_Category $category): self
    {
        if (!$category->getId()) {
            return $this;
        }

        $ruleData = $category->getDynamicRuleData();

        // Get existing rules for this category
        $collection = Mage::getResourceModel('catalog/category_dynamic_rule_collection')
            ->addCategoryFilter($category->getId());

        // Clear existing rules
        foreach ($collection as $rule) {
            $rule->delete();
        }

        // Always save rule if we have rule data, regardless of is_dynamic setting
        $rule = Mage::getModel('catalog/category_dynamic_rule');
        $rule->setCategoryId($category->getId());
        $rule->setIsActive($category->getIsDynamic() ? 1 : 0);

        // Process the conditions if present
        if (isset($ruleData['conditions']) && !empty($ruleData['conditions'])) {
            $rule->loadPost($ruleData);
        } else {
            // Set empty conditions
            $rule->getConditions()->setConditions([]);
        }

        $rule->save();

        return $this;
    }
}
