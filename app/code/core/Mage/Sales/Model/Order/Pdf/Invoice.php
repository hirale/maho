<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Order_Pdf_Invoice extends Mage_Sales_Model_Order_Pdf_Abstract
{
    /**
     * Draw header for item table
     */
    protected function _drawHeader(Zend_Pdf_Page $page)
    {
        /* Add table head */
        $this->_setFontRegular($page, 10);
        $page->setFillColor(new Zend_Pdf_Color_Rgb(0.93, 0.92, 0.92));
        $page->setLineColor(new Zend_Pdf_Color_GrayScale(0.5));
        $page->setLineWidth(0.5);
        $page->drawRectangle(25, $this->y, 570, $this->y - 15);
        $this->y -= 10;
        $page->setFillColor(new Zend_Pdf_Color_Rgb(0, 0, 0));

        //columns headers
        $lines[0][] = [
            'text' => Mage::helper('sales')->__('Products'),
            'feed' => 35,
        ];

        $lines[0][] = [
            'text'  => Mage::helper('sales')->__('SKU'),
            'feed'  => 290,
            'align' => 'right',
        ];

        $lines[0][] = [
            'text'  => Mage::helper('sales')->__('Qty'),
            'feed'  => 435,
            'align' => 'right',
        ];

        $lines[0][] = [
            'text'  => Mage::helper('sales')->__('Price'),
            'feed'  => 360,
            'align' => 'right',
        ];

        $lines[0][] = [
            'text'  => Mage::helper('sales')->__('Tax'),
            'feed'  => 495,
            'align' => 'right',
        ];

        $lines[0][] = [
            'text'  => Mage::helper('sales')->__('Subtotal'),
            'feed'  => 565,
            'align' => 'right',
        ];

        $lineBlock = [
            'lines'  => $lines,
            'height' => 5,
        ];

        $this->drawLineBlocks($page, [$lineBlock], ['table_header' => true]);
        $page->setFillColor(new Zend_Pdf_Color_GrayScale(0));
        $this->y -= 20;
    }

    /**
     * Return PDF document
     *
     * @param  Mage_Sales_Model_Order_Invoice[] $invoices
     * @return Zend_Pdf
     */
    #[\Override]
    public function getPdf($invoices = [])
    {
        $this->_beforeGetPdf();
        $this->_initRenderer('invoice');

        $pdf = new Zend_Pdf();
        $this->_setPdf($pdf);
        $style = new Zend_Pdf_Style();
        $this->_setFontBold($style, 10);

        foreach ($invoices as $invoice) {
            if ($invoice->getStoreId()) {
                Mage::app()->getLocale()->emulate($invoice->getStoreId());
                Mage::app()->setCurrentStore($invoice->getStoreId());
            }
            $page  = $this->newPage();
            $order = $invoice->getOrder();
            /* Add image */
            $this->insertLogo($page, $invoice->getStore());
            /* Add address */
            $this->insertAddress($page, $invoice->getStore());
            /* Add head */
            $this->insertOrder(
                $page,
                $order,
                Mage::getStoreConfigFlag(self::XML_PATH_SALES_PDF_INVOICE_PUT_ORDER_ID, $order->getStoreId()),
            );
            /* Add document text and number */
            $this->insertDocumentNumber(
                $page,
                Mage::helper('sales')->__('Invoice # ') . $invoice->getIncrementId(),
            );
            /* Add table */
            $this->_drawHeader($page);
            /* Add body */
            foreach ($invoice->getAllItems() as $item) {
                if ($item->getOrderItem()->getParentItem()) {
                    continue;
                }
                /* Draw item */
                $this->_drawItem($item, $page, $order);
                $page = end($pdf->pages);
            }
            /* Add totals */
            $this->insertTotals($page, $invoice);
            if ($invoice->getStoreId()) {
                Mage::app()->getLocale()->revert();
            }
        }
        $this->_afterGetPdf();
        return $pdf;
    }

    /**
     * Create new page and assign to PDF object
     *
     * @return Zend_Pdf_Page
     */
    #[\Override]
    public function newPage(array $settings = [])
    {
        /* Add new table head */
        $page = $this->_getPdf()->newPage(Zend_Pdf_Page::SIZE_A4);
        $this->_getPdf()->pages[] = $page;
        $this->y = 800;
        if (!empty($settings['table_header'])) {
            $this->_drawHeader($page);
        }
        return $page;
    }
}
