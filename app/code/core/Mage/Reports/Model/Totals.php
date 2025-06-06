<?php

/**
 * Maho
 *
 * @package    Mage_Reports
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2025 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Reports_Model_Totals
{
    /**
     * Retrieve count totals
     *
     * @param Mage_Adminhtml_Block_Report_Grid $grid
     * @param string $from
     * @param string $to
     * @return Varien_Object
     */
    public function countTotals($grid, $from, $to)
    {
        $columns = [];
        foreach ($grid->getColumns() as $col) {
            if ($col->getTotal() === null) {
                continue;
            }
            $columns[$col->getIndex()] = ['total' => $col->getTotal(), 'value' => 0];
        }

        $count = 0;
        $report = $grid->getCollection()->getReportFull($from, $to);
        foreach ($report as $item) {
            if ($grid->getSubReportSize() && $count >= $grid->getSubReportSize()) {
                continue;
            }
            $data = $item->getData();

            foreach (array_keys($columns) as $field) {
                if ($field !== '') {
                    $columns[$field]['value'] += $data[$field] ?? 0;
                }
            }
            $count++;
        }
        $data = [];
        foreach ($columns as $field => $a) {
            if ($a['total'] == 'avg') {
                if ($field !== '') {
                    if ($count != 0) {
                        $data[$field] = $a['value'] / $count;
                    } else {
                        $data[$field] = 0;
                    }
                }
            } elseif ($a['total'] == 'sum') {
                if ($field !== '') {
                    $data[$field] = $a['value'];
                }
            } elseif (str_contains($a['total'], '/')) {
                if ($field !== '') {
                    $data[$field] = 0;
                }
            }
        }

        $totals = new Varien_Object();
        $totals->setData($data);

        return $totals;
    }
}
