<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Sales_Order_Create_Comment extends Mage_Adminhtml_Block_Sales_Order_Create_Abstract
{
    protected $_form;

    /**
     * @return string
     */
    public function getHeaderCssClass()
    {
        return 'head-comment';
    }

    /**
     * @return string
     */
    public function getHeaderText()
    {
        return Mage::helper('sales')->__('Order Comment');
    }

    /**
     * @return string
     */
    public function getCommentNote()
    {
        return $this->escapeHtml($this->getQuote()->getCustomerNote());
    }

    /**
     * @return bool
     */
    public function getNoteNotify()
    {
        $notify = $this->getQuote()->getCustomerNoteNotify();
        if (is_null($notify) || $notify) {
            return true;
        }
        return false;
    }
}
