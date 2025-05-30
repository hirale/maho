<?php

/**
 * Maho
 *
 * @package    Mage_Tag
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method Mage_Catalog_Model_Product[] getItems()
 */
class Mage_Tag_Model_Resource_Product_Collection extends Mage_Catalog_Model_Resource_Product_Collection
{
    /**
     * Customer Id Filter
     *
     * @var int
     */
    protected $_customerFilterId;

    /**
     * Tag Id Filter
     *
     * @var int
     */
    protected $_tagIdFilter;

    /**
     * Join Flags
     *
     * @var array
     */
    protected $_joinFlags            = [];

    /**
     * Initialize collection select
     *
     * @return $this
     */
    #[\Override]
    protected function _initSelect()
    {
        parent::_initSelect();

        $this->_joinFields();
        $this->getSelect()->group('e.entity_id');

        /*
         * Allow analytic function usage
         */
        $this->_useAnalyticFunction = true;

        return $this;
    }

    /**
     * Set flag about joined table.
     * setFlag method must be used in future.
     *
     * @deprecated after 1.3.2.3
     *
     * @param string $table
     * @return $this
     */
    public function setJoinFlag($table)
    {
        $this->setFlag($table, true);
        return $this;
    }

    /**
     * Get flag's status about joined table.
     * getFlag method must be used in future.
     *
     * @deprecated after 1.3.2.3
     *
     * @param string $table
     * @return bool
     */
    public function getJoinFlag($table)
    {
        return $this->getFlag($table);
    }

    /**
     * Unset value of join flag.
     * Set false (bool) value to flag instead in future.
     *
     * @deprecated after 1.3.2.3
     *
     * @param string $table
     * @return $this
     */
    public function unsetJoinFlag($table = null)
    {
        $this->setFlag($table, false);
        return $this;
    }

    /**
     * Add tag visibility on stores
     *
     * @return $this
     */
    public function addStoresVisibility()
    {
        $this->setFlag('add_stores_after', true);
        return $this;
    }

    /**
     * Add tag visibility on stores process
     *
     * @return $this
     */
    protected function _addStoresVisibility()
    {
        $tagIds = [];
        foreach ($this as $item) {
            $tagIds[] = $item->getTagId();
        }

        $tagsStores = [];
        if (count($tagIds)) {
            $select = $this->getConnection()->select()
                ->from($this->getTable('tag/relation'), ['store_id', 'tag_id'])
                ->where('tag_id IN(?)', $tagIds);
            $tagsRaw = $this->getConnection()->fetchAll($select);
            foreach ($tagsRaw as $tag) {
                if (!isset($tagsStores[$tag['tag_id']])) {
                    $tagsStores[$tag['tag_id']] = [];
                }

                $tagsStores[$tag['tag_id']][] = $tag['store_id'];
            }
        }

        foreach ($this as $item) {
            if (isset($tagsStores[$item->getTagId()])) {
                $item->setStores($tagsStores[$item->getTagId()]);
            } else {
                $item->setStores([]);
            }
        }

        return $this;
    }

    /**
     * Add group by tag
     *
     * @return $this
     */
    public function addGroupByTag()
    {
        $this->getSelect()->group('relation.tag_relation_id');
        return $this;
    }

    /**
     * Add Store ID filter
     *
     * @param int|array $store
     * @return $this
     */
    #[\Override]
    public function addStoreFilter($store = null)
    {
        if (!is_null($store)) {
            $this->getSelect()->where('relation.store_id IN (?)', $store);
        }
        return $this;
    }

    /**
     * Set Customer filter
     * If incoming parameter is array and has element with key 'null'
     * then condition with IS NULL or IS NOT NULL will be added.
     * Otherwise condition with IN() will be added
     *
     * @param int|array $customerId
     * @return $this
     */
    public function addCustomerFilter($customerId)
    {
        if (is_array($customerId) && isset($customerId['null'])) {
            $condition = ($customerId['null']) ? 'IS NULL' : 'IS NOT NULL';
            $this->getSelect()->where('relation.customer_id ' . $condition);
            return $this;
        }
        $this->getSelect()->where('relation.customer_id IN(?)', $customerId);
        $this->_customerFilterId = $customerId;
        return $this;
    }

    /**
     * Set tag filter
     *
     * @param int $tagId
     * @return $this
     */
    public function addTagFilter($tagId)
    {
        $this->getSelect()->where('relation.tag_id = ?', $tagId);
        $this->setFlag('distinct', true);
        return $this;
    }

    /**
     * Add tag status filter
     *
     * @param int $status
     * @return $this
     */
    public function addStatusFilter($status)
    {
        $this->getSelect()->where('t.status = ?', $status);
        return $this;
    }

    /**
     * Set DESC order to collection
     *
     * @param string $dir
     * @return $this
     */
    public function setDescOrder($dir = 'DESC')
    {
        $this->setOrder('relation.tag_relation_id', $dir);
        return $this;
    }

    /**
     * Add Popularity
     *
     * @param int $tagId
     * @param int $storeId
     * @return $this
     */
    public function addPopularity($tagId, $storeId = null)
    {
        $tagRelationTable = $this->getTable('tag/relation');

        $condition = [
            'prelation.product_id=e.entity_id',
        ];

        if (!is_null($storeId)) {
            $condition[] = $this->getConnection()->quoteInto('prelation.store_id = ?', $storeId);
        }
        $condition = implode(' AND ', $condition);
        $innerSelect = $this->getConnection()->select()
            ->from(
                ['relation' => $tagRelationTable],
                ['product_id', 'store_id', 'popularity' => 'COUNT(DISTINCT relation.tag_relation_id)'],
            )
            ->where('relation.tag_id = ?', $tagId)
            ->group(['product_id', 'store_id']);

        $this->getSelect()
            ->joinLeft(
                ['prelation' => $innerSelect],
                $condition,
                ['popularity' => 'prelation.popularity'],
            );

        $this->_tagIdFilter = $tagId;
        $this->setFlag('prelation', true);
        return $this;
    }

    /**
     * Add Popularity Filter
     *
     * @param mixed $condition
     * @return $this
     */
    public function addPopularityFilter($condition)
    {
        $tagRelationTable = Mage::getSingleton('core/resource')
            ->getTableName('tag/relation');

        $select = $this->getConnection()->select()
            ->from($tagRelationTable, ['product_id', 'popularity' => 'COUNT(DISTINCT tag_relation_id)'])
            ->where('tag_id = :tag_id')
            ->group('product_id')
            ->having($this->_getConditionSql('popularity', $condition));

        $prodIds = [];
        foreach ($this->getConnection()->fetchAll($select, ['tag_id' => $this->_tagIdFilter]) as $item) {
            $prodIds[] = $item['product_id'];
        }

        if (count($prodIds)) {
            $this->getSelect()->where('e.entity_id IN(?)', $prodIds);
        } else {
            $this->getSelect()->where('e.entity_id IN(0)');
        }

        return $this;
    }

    /**
     * Set tag active filter to collection
     *
     * @return $this
     */
    public function setActiveFilter()
    {
        $active = Mage_Tag_Model_Tag_Relation::STATUS_ACTIVE;
        $this->getSelect()->where('relation.active = ?', $active);
        if ($this->getFlag('prelation')) {
            $this->getSelect()->where('prelation.active = ?', $active);
        }
        return $this;
    }

    /**
     * Add Product Tags
     *
     * @param int $storeId
     * @return $this
     */
    public function addProductTags($storeId = null)
    {
        foreach ($this->getItems() as $item) {
            $tagsCollection = Mage::getModel('tag/tag')->getResourceCollection();

            if (!is_null($storeId)) {
                $tagsCollection->addStoreFilter($storeId);
            }

            $tagsCollection->addPopularity()
                ->addProductFilter($item->getEntityId())
                ->addCustomerFilter($this->_customerFilterId)
                ->setActiveFilter();

            $tagsCollection->load();
            $item->setProductTags($tagsCollection);
        }

        return $this;
    }

    /**
     * Join fields process
     *
     * @return $this
     */
    protected function _joinFields()
    {
        $tagTable           = $this->getTable('tag/tag');
        $tagRelationTable   = $this->getTable('tag/relation');

        $this->addAttributeToSelect('name')
            ->addAttributeToSelect('price')
            ->addAttributeToSelect('small_image');

        $this->getSelect()
            ->join(['relation' => $tagRelationTable], 'relation.product_id = e.entity_id', [
                'product_id'    => 'product_id',
                'item_store_id' => 'store_id',
            ])
            ->join(
                ['t' => $tagTable],
                't.tag_id = relation.tag_id',
                [
                    'tag_id',
                    'tag_status' => 'status',
                    'tag_name'   => 'name',
                    'store_id'   => $this->getConnection()->getCheckSql(
                        't.first_store_id = 0',
                        'relation.store_id',
                        't.first_store_id',
                    ),
                ],
            );

        return $this;
    }

    /**
     * After load adding data
     *
     * @return $this
     */
    #[\Override]
    protected function _afterLoad()
    {
        parent::_afterLoad();

        if ($this->getFlag('add_stores_after')) {
            $this->_addStoresVisibility();
        }

        if (count($this) > 0) {
            Mage::dispatchEvent('tag_tag_product_collection_load_after', [
                'collection' => $this,
            ]);
        }

        return $this;
    }

    /**
     * Render SQL for retrieve product count
     *
     * @return Varien_Db_Select
     */
    #[\Override]
    public function getSelectCountSql()
    {
        $countSelect = clone $this->getSelect();

        $countSelect->reset(Zend_Db_Select::COLUMNS);
        $countSelect->reset(Zend_Db_Select::ORDER);
        $countSelect->reset(Zend_Db_Select::LIMIT_COUNT);
        $countSelect->reset(Zend_Db_Select::LIMIT_OFFSET);
        $countSelect->reset(Zend_Db_Select::GROUP);

        if ($this->getFlag('group_tag')) {
            $field = 'relation.tag_id';
        } else {
            $field = 'e.entity_id';
        }
        $expr = new Zend_Db_Expr('COUNT('
            . ($this->getFlag('distinct') ? 'DISTINCT ' : '')
            . $field . ')');

        $countSelect->columns($expr);

        return $countSelect;
    }

    /**
     * Treat "order by" items as attributes to sort
     *
     * @return $this
     */
    #[\Override]
    protected function _renderOrders()
    {
        if (!$this->_isOrdersRendered) {
            parent::_renderOrders();

            $orders = $this->getSelect()
                ->getPart(Zend_Db_Select::ORDER);

            $appliedOrders = [];
            foreach ($orders as $order) {
                $appliedOrders[(string) $order[0]] = true;
            }

            foreach ($this->_orders as $field => $direction) {
                if (empty($appliedOrders[$field])) {
                    $this->_select->order(new Zend_Db_Expr($field . ' ' . $direction));
                }
            }
        }
        return $this;
    }

    /**
     * Set Id Fieldname as Tag Relation Id
     *
     * @return $this
     */
    public function setRelationId()
    {
        $this->_setIdFieldName('tag_relation_id');
        return $this;
    }
}
