<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Sales_Order_Create_Messages extends Mage_Adminhtml_Block_Messages
{
    #[\Override]
    public function _prepareLayout()
    {
        $this->addMessages(Mage::getSingleton('adminhtml/session_quote')->getMessages(true));
        return parent::_prepareLayout();
    }
}
