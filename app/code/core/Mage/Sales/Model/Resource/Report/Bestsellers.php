<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Resource_Report_Bestsellers extends Mage_Sales_Model_Resource_Report_Abstract
{
    public const AGGREGATION_DAILY   = 'daily';
    public const AGGREGATION_MONTHLY = 'monthly';
    public const AGGREGATION_YEARLY  = 'yearly';

    /**
     * Model initialization
     */
    #[\Override]
    protected function _construct()
    {
        $this->_init('sales/bestsellers_aggregated_' . self::AGGREGATION_DAILY, 'id');
    }

    /**
     * Aggregate Orders data by order created at
     *
     * @param mixed $from
     * @param mixed $to
     * @return $this
     */
    public function aggregate($from = null, $to = null)
    {
        // convert input dates to UTC to be comparable with DATETIME fields in DB
        $from    = $this->_dateToUtc($from);
        $to      = $this->_dateToUtc($to);

        $this->_checkDates($from, $to);
        $adapter = $this->_getWriteAdapter();
        //$this->_getWriteAdapter()->beginTransaction();

        try {
            if ($from !== null || $to !== null) {
                $subSelect = $this->_getTableDateRangeSelect(
                    $this->getTable('sales/order'),
                    'created_at',
                    'updated_at',
                    $from,
                    $to,
                );
            } else {
                $subSelect = null;
            }

            $this->_clearTableByDateRange($this->getMainTable(), $from, $to, $subSelect);
            // convert dates from UTC to current admin timezone
            $periodExpr = $adapter->getDatePartSql(
                $this->getStoreTZOffsetQuery(
                    ['source_table' => $this->getTable('sales/order')],
                    'source_table.created_at',
                    $from,
                    $to,
                ),
            );

            /** @var Mage_Core_Model_Resource_Helper_Mysql4 $helper */
            $helper = Mage::getResourceHelper('core');
            $select = $adapter->select();

            $select->group([
                $periodExpr,
                'source_table.store_id',
                'order_item.product_id',
            ]);

            $columns = [
                'period'                 => $periodExpr,
                'store_id'               => 'source_table.store_id',
                'product_id'             => 'order_item.product_id',
                'product_type_id'        => 'product.type_id',
                'product_name'           => new Zend_Db_Expr(
                    sprintf(
                        'MIN(%s)',
                        $adapter->getIfNullSql('product_name.value', 'product_default_name.value'),
                    ),
                ),
                'product_price'          => new Zend_Db_Expr(
                    sprintf(
                        '%s',
                        $helper->prepareColumn(
                            sprintf(
                                'MIN(%s)',
                                $adapter->getIfNullSql(
                                    $adapter->getIfNullSql('product_price.value', 'product_default_price.value'),
                                    0,
                                ),
                            ),
                            $select->getPart(Zend_Db_Select::GROUP),
                        ),
                    ),
                ),
                'qty_ordered'            => new Zend_Db_Expr('SUM(order_item.qty_ordered)'),
            ];

            $select
                ->from(
                    [
                        'source_table' => $this->getTable('sales/order')],
                    $columns,
                )
                ->joinInner(
                    [
                        'order_item' => $this->getTable('sales/order_item')],
                    'order_item.order_id = source_table.entity_id',
                    [],
                )
                ->where('source_table.state != ?', Mage_Sales_Model_Order::STATE_CANCELED);

            /** @var Mage_Catalog_Model_Resource_Product $product */
            $product  = Mage::getResourceSingleton('catalog/product');

            $joinExpr = [
                'product.entity_id = order_item.product_id',
                $adapter->quoteInto('product.entity_type_id = ?', $product->getTypeId()),
            ];

            $joinExpr = implode(' AND ', $joinExpr);
            $select->joinInner(
                [
                    'product' => $this->getTable('catalog/product')],
                $joinExpr,
                [],
            );

            // join product attributes Name & Price
            $attr     = $product->getAttribute('name');
            $joinExprProductName       = [
                'product_name.entity_id = product.entity_id',
                'product_name.store_id = source_table.store_id',
                $adapter->quoteInto('product_name.entity_type_id = ?', $product->getTypeId()),
                $adapter->quoteInto('product_name.attribute_id = ?', $attr->getAttributeId()),
            ];
            $joinExprProductName        = implode(' AND ', $joinExprProductName);
            $joinExprProductDefaultName = [
                'product_default_name.entity_id = product.entity_id',
                'product_default_name.store_id = 0',
                $adapter->quoteInto('product_default_name.entity_type_id = ?', $product->getTypeId()),
                $adapter->quoteInto('product_default_name.attribute_id = ?', $attr->getAttributeId()),
            ];
            $joinExprProductDefaultName = implode(' AND ', $joinExprProductDefaultName);
            $select->joinLeft(
                [
                    'product_name' => $attr->getBackend()->getTable()],
                $joinExprProductName,
                [],
            )
            ->joinLeft(
                [
                    'product_default_name' => $attr->getBackend()->getTable()],
                $joinExprProductDefaultName,
                [],
            );
            $attr                    = $product->getAttribute('price');
            $joinExprProductPrice    = [
                'product_price.entity_id = product.entity_id',
                'product_price.store_id = source_table.store_id',
                $adapter->quoteInto('product_price.entity_type_id = ?', $product->getTypeId()),
                $adapter->quoteInto('product_price.attribute_id = ?', $attr->getAttributeId()),
            ];
            $joinExprProductPrice    = implode(' AND ', $joinExprProductPrice);

            $joinExprProductDefPrice = [
                'product_default_price.entity_id = product.entity_id',
                'product_default_price.store_id = 0',
                $adapter->quoteInto('product_default_price.entity_type_id = ?', $product->getTypeId()),
                $adapter->quoteInto('product_default_price.attribute_id = ?', $attr->getAttributeId()),
            ];
            $joinExprProductDefPrice = implode(' AND ', $joinExprProductDefPrice);
            $select->joinLeft(
                ['product_price' => $attr->getBackend()->getTable()],
                $joinExprProductPrice,
                [],
            )
            ->joinLeft(
                ['product_default_price' => $attr->getBackend()->getTable()],
                $joinExprProductDefPrice,
                [],
            );

            if ($subSelect !== null) {
                $select->having($this->_makeConditionFromDateRangeSelect($subSelect, 'period'));
            }

            $select->useStraightJoin();  // important!
            $insertQuery = $helper->getInsertFromSelectUsingAnalytic(
                $select,
                $this->getMainTable(),
                array_keys($columns),
            );
            $adapter->query($insertQuery);

            $this->_aggregateDefault($subSelect);

            // update rating
            $this->_updateRatingPos(self::AGGREGATION_DAILY);
            $this->_updateRatingPos(self::AGGREGATION_MONTHLY);
            $this->_updateRatingPos(self::AGGREGATION_YEARLY);

            $this->_setFlagData(Mage_Reports_Model_Flag::REPORT_BESTSELLERS_FLAG_CODE);
        } catch (Exception $e) {
            //$this->_getWriteAdapter()->rollBack();
            throw $e;
        }

        //$this->_getWriteAdapter()->commit();
        return $this;
    }

    /**
     * Aggregate Orders data for default store
     *
     * @param Varien_Db_Select|null $subSelect
     * @return $this
     */
    protected function _aggregateDefault($subSelect = null)
    {
        $adapter    = $this->_getWriteAdapter();
        $select     = $adapter->select();
        /** @var Mage_Catalog_Model_Resource_Product $product */
        $product    = Mage::getResourceSingleton('catalog/product');
        $attr       = $product->getAttribute('price');
        /** @var Mage_Core_Model_Resource_Helper_Mysql4 $helper */
        $helper     = Mage::getResourceHelper('core');

        $columns = [
            'period'            => 'period',
            'store_id'          => new Zend_Db_Expr((string) Mage_Core_Model_App::ADMIN_STORE_ID),
            'product_id'        => 'product_id',
            'product_type_id'   => 'product_type_id',
            'product_name'      => new Zend_Db_Expr('MIN(product_name)'),
            'product_price'     => new Zend_Db_Expr(
                sprintf(
                    '%s',
                    $helper->prepareColumn(
                        sprintf(
                            'MIN(%s)',
                            $adapter->getIfNullSql('product_default_price.value', 0),
                        ),
                        $select->getPart(Zend_Db_Select::GROUP),
                    ),
                ),
            ),
            'qty_ordered'       => new Zend_Db_Expr('SUM(qty_ordered)'),
        ];

        $select->from($this->getMainTable(), $columns)
            ->where($this->getMainTable() . '.store_id <> ?', 0);
        $joinExprProductDefPrice = [
            'product_default_price.entity_id = ' . $this->getMainTable() . '.product_id',
            'product_default_price.store_id = 0',
            $adapter->quoteInto('product_default_price.entity_type_id = ?', $product->getTypeId()),
            $adapter->quoteInto('product_default_price.attribute_id = ?', $attr->getAttributeId()),
        ];
        $joinExprProductDefPrice = implode(' AND ', $joinExprProductDefPrice);
        $select->joinLeft(
            ['product_default_price' => $attr->getBackend()->getTable()],
            $joinExprProductDefPrice,
            [],
        );

        if ($subSelect !== null) {
            $select->where($this->_makeConditionFromDateRangeSelect($subSelect, 'period'));
        }

        $select->group([
            'period',
            'product_id',
        ]);

        $insertQuery = $helper->getInsertFromSelectUsingAnalytic(
            $select,
            $this->getMainTable(),
            array_keys($columns),
        );
        $adapter->query($insertQuery);

        return $this;
    }

    /**
     * Update rating position
     *
     * @param string $aggregation One of Mage_Sales_Model_Resource_Report_Bestsellers::AGGREGATION_XXX constants
     * @return $this
     */
    protected function _updateRatingPos($aggregation)
    {
        $aggregationTable   = $this->getTable('sales/bestsellers_aggregated_' . $aggregation);

        $aggregationAliases = [
            'daily'   => self::AGGREGATION_DAILY,
            'monthly' => self::AGGREGATION_MONTHLY,
            'yearly'  => self::AGGREGATION_YEARLY,
        ];

        /** @var Mage_Sales_Model_Resource_Helper_Mysql4 $helper */
        $helper = Mage::getResourceHelper('sales');
        $helper->getBestsellersReportUpdateRatingPos(
            $aggregation,
            $aggregationAliases,
            $this->getMainTable(),
            $aggregationTable,
        );

        return $this;
    }
}
