<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2021-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Model_System_Config_Source_Cookie_Samesite
{
    /**
     * @return array[]
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => 'None', 'label' => Mage::helper('adminhtml')->__('None')],
            ['value' => 'Strict', 'label' => Mage::helper('adminhtml')->__('Strict')],
            ['value' => 'Lax', 'label' => Mage::helper('adminhtml')->__('Lax')],
        ];
    }
}
