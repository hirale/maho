<?php

/**
 * Maho
 *
 * @package    Mage_Rule
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Rule_Model_Resource_Rule_Condition_SqlBuilder
{
    /**
     * Database adapter
     * @var Varien_Db_Adapter_Interface
     */
    protected $_adapter;

    public function __construct(array $config = [])
    {
        $this->_adapter = $config['adapter'] ?? Mage::getSingleton('core/resource')->getConnection(Mage_Core_Model_Resource::DEFAULT_READ_RESOURCE);
    }

    /**
     * Convert operator for sql where
     *
     * @param string $field
     * @param string $operator
     * @param string|array $value
     * @return string
     */
    public function getOperatorCondition($field, $operator, $value)
    {
        switch ($operator) {
            case '!=':
            case '>=':
            case '<=':
            case '>':
            case '<':
                $selectOperator = sprintf('%s?', $operator);
                break;
            case '{}':
            case '!{}':
                if (preg_match('/^.*(category_id)$/', $field) && is_array($value)) {
                    $selectOperator = ' IN (?)';
                } else {
                    $selectOperator = ' LIKE ?';
                }
                if (str_starts_with($operator, '!')) {
                    $selectOperator = ' NOT' . $selectOperator;
                }
                break;

            case '[]':
            case '![]':
            case '()':
            case '!()':
                $selectOperator = 'FIND_IN_SET(?,' . $this->_adapter->quoteIdentifier($field) . ')';
                if (str_starts_with($operator, '!')) {
                    $selectOperator = 'NOT ' . $selectOperator;
                }
                break;

            default:
                $selectOperator = '=?';
                break;
        }
        $field = $this->_adapter->quoteIdentifier($field);

        if (is_array($value) && in_array($operator, ['==', '!=', '>=', '<=', '>', '<', '{}', '!{}'])) {
            $results = [];
            foreach ($value as $v) {
                $results[] = $this->_adapter->quoteInto("{$field}{$selectOperator}", $v);
            }
            $result = implode(' AND ', $results);
        } elseif (in_array($operator, ['()', '!()', '[]', '![]'])) {
            if (!is_array($value)) {
                $value = [$value];
            }

            $results = [];
            foreach ($value as $v) {
                $results[] = $this->_adapter->quoteInto("{$selectOperator}", $v);
            }
            $result = implode(in_array($operator, ['()', '!()']) ? ' OR ' : ' AND ', $results);
        } else {
            $result = $this->_adapter->quoteInto("{$field}{$selectOperator}", $value);
        }
        return $result;
    }
}
