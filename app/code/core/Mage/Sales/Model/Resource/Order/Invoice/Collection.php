<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Resource_Order_Invoice_Collection extends Mage_Sales_Model_Resource_Order_Collection_Abstract
{
    /**
     * @var string
     */
    protected $_eventPrefix    = 'sales_order_invoice_collection';

    /**
     * @var string
     */
    protected $_eventObject    = 'order_invoice_collection';

    /**
     * Order field for setOrderFilter
     *
     * @var string
     */
    protected $_orderField     = 'order_id';

    #[\Override]
    protected function _construct()
    {
        $this->_init('sales/order_invoice');
    }

    /**
     * Used to emulate after load functionality for each item without loading them
     * @return $this
     */
    #[\Override]
    protected function _afterLoad()
    {
        $this->walk('afterLoad');
        return $this;
    }
}
