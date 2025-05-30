<?php

/**
 * Maho
 *
 * @package    Mage_Reports
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Reports_Model_Resource_Tag_Product_Collection extends Mage_Tag_Model_Resource_Product_Collection
{
    #[\Override]
    protected function _construct()
    {
        parent::_construct();
        /**
         * Allow to use analytic function
         */
        $this->_useAnalyticFunction = true;
    }
    /**
     * Add unique target count to result
     *
     * @return $this
     */
    public function addUniqueTagedCount()
    {
        $select = clone $this->getSelect();

        $select->reset()
            ->from(['rel' => $this->getTable('tag/relation')], 'COUNT(DISTINCT rel.tag_id)')
            ->where('rel.product_id = e.entity_id');

        $this->getSelect()
            ->columns(['utaged' => new Zend_Db_Expr(sprintf('(%s)', $select))]);
        return $this;
    }

    /**
     * Add all target count to result
     *
     * @return $this
     */
    public function addAllTagedCount()
    {
        $this->getSelect()
            ->columns(['taged' => 'COUNT(relation.tag_id)']);
        return $this;
    }

    /**
     * Add target count to result
     *
     * @return $this
     */
    public function addTagedCount()
    {
        $this->getSelect()
            ->columns(['taged' => 'COUNT(relation.tag_relation_id)']);

        return $this;
    }

    /**
     * Add group by product to result
     *
     * @return $this
     */
    public function addGroupByProduct()
    {
        $this->getSelect()
            ->group('relation.product_id');
        $this->setFlag('distinct', true);
        return $this;
    }

    /**
     * Add group by tag to result
     *
     * @return $this
     */
    #[\Override]
    public function addGroupByTag()
    {
        $this->getSelect()
            ->group('relation.tag_id');
        $this->setFlag('distinct', true);
        $this->setFlag('group_tag', true);
        return $this;
    }

    /**
     * Add product filter
     *
     * @param int $customerId
     * @return $this
     */
    public function addProductFilter($customerId)
    {
        $this->getSelect()
             ->where('relation.product_id = ?', (int) $customerId);
        $this->_customerFilterId = (int) $customerId;
        return $this;
    }

    /**
     * Set order
     *
     * @param string $attribute
     * @param string $dir
     * @return $this
     */
    #[\Override]
    public function setOrder($attribute, $dir = self::SORT_ORDER_DESC)
    {
        if ($attribute == 'utaged' || $attribute == 'taged' || $attribute == 'tag_name') {
            $this->getSelect()->order($attribute . ' ' . $dir);
        } else {
            parent::setOrder($attribute, $dir);
        }

        return $this;
    }

    /**
     * Join fields
     *
     * @return $this
     */
    #[\Override]
    protected function _joinFields()
    {
        $this->addAttributeToSelect('name');
        $this->getSelect()
            ->join(
                ['relation' => $this->getTable('tag/relation')],
                'relation.product_id = e.entity_id',
                [],
            )
            ->join(
                ['t' => $this->getTable('tag/tag')],
                't.tag_id = relation.tag_id',
                ['tag_id',  'status', 'tag_name' => 'name'],
            );

        return $this;
    }
}
