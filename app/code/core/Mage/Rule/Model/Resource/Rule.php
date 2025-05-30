<?php

/**
 * Maho
 *
 * @package    Mage_Rule
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Abstract Rule entity resource model
 *
 * @deprecated since 1.7.0.0 use Mage_Rule_Model_Resource_Abstract instead
 */
class Mage_Rule_Model_Resource_Rule extends Mage_Rule_Model_Resource_Abstract
{
    #[\Override]
    protected function _construct()
    {
        $this->_init('rule/rule', 'rule_id');
    }
}
