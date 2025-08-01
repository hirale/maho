<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Resource_Helper_Mysql4 extends Mage_Core_Model_Resource_Helper_Mysql4 implements Mage_Sales_Model_Resource_Helper_Interface
{
    /**
     * Update rating position
     *
     * @param string $aggregation One of Mage_Sales_Model_Resource_Report_Bestsellers::AGGREGATION_XXX constants
     * @param array $aggregationAliases
     * @param string $mainTable
     * @param string $aggregationTable
     * @return Mage_Sales_Model_Resource_Helper_Mysql4
     */
    #[\Override]
    public function getBestsellersReportUpdateRatingPos(
        $aggregation,
        $aggregationAliases,
        $mainTable,
        $aggregationTable,
    ) {
        /** @var Mage_Reports_Model_Resource_Helper_Interface $reportsResourceHelper */
        $reportsResourceHelper = Mage::getResourceHelper('reports');

        if ($aggregation == $aggregationAliases['monthly']) {
            $reportsResourceHelper
                ->updateReportRatingPos('month', 'qty_ordered', $mainTable, $aggregationTable);
        } elseif ($aggregation == $aggregationAliases['yearly']) {
            $reportsResourceHelper
                ->updateReportRatingPos('year', 'qty_ordered', $mainTable, $aggregationTable);
        } else {
            $reportsResourceHelper
                ->updateReportRatingPos('day', 'qty_ordered', $mainTable, $aggregationTable);
        }

        return $this;
    }
}
