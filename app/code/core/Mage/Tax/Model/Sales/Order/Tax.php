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

/**
 * @method Mage_Tax_Model_Resource_Sales_Order_Tax _getResource()
 * @method Mage_Tax_Model_Resource_Sales_Order_Tax getResource()
 * @method Mage_Tax_Model_Resource_Sales_Order_Tax_Collection getCollection()
 *
 * @method int getOrderId()
 * @method $this setOrderId(int $value)
 * @method string getCode()
 * @method $this setCode(string $value)
 * @method string getTitle()
 * @method $this setTitle(string $value)
 * @method float getPercent()
 * @method $this setPercent(float $value)
 * @method float getAmount()
 * @method $this setAmount(float $value)
 * @method int getPriority()
 * @method $this setPriority(int $value)
 * @method int getPosition()
 * @method $this setPosition(int $value)
 * @method float getBaseAmount()
 * @method $this setBaseAmount(float $value)
 * @method int getProcess()
 * @method $this setProcess(int $value)
 * @method float getBaseRealAmount()
 * @method $this setBaseRealAmount(float $value)
 * @method int getHidden()
 * @method $this setHidden(int $value)
 */
class Mage_Tax_Model_Sales_Order_Tax extends Mage_Core_Model_Abstract
{
    #[\Override]
    protected function _construct()
    {
        $this->_init('tax/sales_order_tax');
    }
}
