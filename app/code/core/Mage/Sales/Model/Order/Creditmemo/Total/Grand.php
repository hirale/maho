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

class Mage_Sales_Model_Order_Creditmemo_Total_Grand extends Mage_Sales_Model_Order_Creditmemo_Total_Abstract
{
    /**
     * @return $this
     */
    #[\Override]
    public function collect(Mage_Sales_Model_Order_Creditmemo $creditmemo)
    {
        $grandTotal     = $creditmemo->getGrandTotal();
        $baseGrandTotal = $creditmemo->getBaseGrandTotal();

        $grandTotal += $creditmemo->getAdjustmentPositive();
        $baseGrandTotal += $creditmemo->getBaseAdjustmentPositive();

        $grandTotal -= $creditmemo->getAdjustmentNegative();
        $baseGrandTotal -= $creditmemo->getBaseAdjustmentNegative();

        $creditmemo->setGrandTotal($grandTotal);
        $creditmemo->setBaseGrandTotal($baseGrandTotal);

        $creditmemo->setAdjustment($creditmemo->getAdjustmentPositive() - $creditmemo->getAdjustmentNegative());
        $creditmemo->setBaseAdjustment($creditmemo->getBaseAdjustmentPositive() - $creditmemo->getBaseAdjustmentNegative());

        return $this;
    }
}
