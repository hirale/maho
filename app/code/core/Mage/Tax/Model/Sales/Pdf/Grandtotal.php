<?php

/**
 * Maho
 *
 * @package    Mage_Tax
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Tax_Model_Sales_Pdf_Grandtotal extends Mage_Sales_Model_Order_Pdf_Total_Default
{
    /**
     * Check if tax amount should be included to grandtotals block
     * array(
     *  $index => array(
     *      'amount'   => $amount,
     *      'label'    => $label,
     *      'font_size'=> $fontSize
     *  )
     * )
     * @return array
     */
    #[\Override]
    public function getTotalsForDisplay()
    {
        $store = $this->getOrder()->getStore();
        $config = Mage::getSingleton('tax/config');
        if (!$config->displaySalesTaxWithGrandTotal($store)) {
            return parent::getTotalsForDisplay();
        }
        $amount = $this->getOrder()->formatPriceTxt($this->getAmount());
        $amountExclTax = $this->getAmount() - $this->getSource()->getTaxAmount();
        $amountExclTax = ($amountExclTax > 0) ? $amountExclTax : 0;
        $amountExclTax = $this->getOrder()->formatPriceTxt($amountExclTax);
        $tax = $this->getOrder()->formatPriceTxt($this->getSource()->getTaxAmount());
        $fontSize = $this->getFontSize() ?: 7;

        $totals = [[
            'amount'    => $this->getAmountPrefix() . $amountExclTax,
            'label'     => Mage::helper('tax')->__('Grand Total (Excl. Tax)') . ':',
            'font_size' => $fontSize,
        ]];

        if ($config->displaySalesFullSummary($store)) {
            $totals = array_merge($totals, $this->getFullTaxInfo());
        }

        $totals[] = [
            'amount'    => $this->getAmountPrefix() . $tax,
            'label'     => Mage::helper('tax')->__('Tax') . ':',
            'font_size' => $fontSize,
        ];
        $totals[] = [
            'amount'    => $this->getAmountPrefix() . $amount,
            'label'     => Mage::helper('tax')->__('Grand Total (Incl. Tax)') . ':',
            'font_size' => $fontSize,
        ];
        return $totals;
    }
}
