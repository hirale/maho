<?php

/**
 * Maho
 *
 * @package    Mage_SalesRule
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_SalesRule_Model_Rule_Condition_Combine extends Mage_Rule_Model_Condition_Combine
{
    public function __construct()
    {
        parent::__construct();
        $this->setType('salesrule/rule_condition_combine');
    }

    /**
     * @return array
     */
    #[\Override]
    public function getNewChildSelectOptions()
    {
        $addressCondition = Mage::getModel('salesrule/rule_condition_address');
        $addressAttributes = $addressCondition->loadAttributeOptions()->getAttributeOption();
        $attributes = [];
        foreach ($addressAttributes as $code => $label) {
            $attributes[] = ['value' => 'salesrule/rule_condition_address|' . $code, 'label' => $label];
        }

        $conditions = parent::getNewChildSelectOptions();
        $conditions = array_merge_recursive($conditions, [
            ['value' => 'salesrule/rule_condition_product_found', 'label' => Mage::helper('salesrule')->__('Product attribute combination')],
            ['value' => 'salesrule/rule_condition_product_subselect', 'label' => Mage::helper('salesrule')->__('Products subselection')],
            ['value' => 'salesrule/rule_condition_combine', 'label' => Mage::helper('salesrule')->__('Conditions combination')],
            ['label' => Mage::helper('salesrule')->__('Cart Attribute'), 'value' => $attributes],
        ]);

        $additional = new Varien_Object();
        Mage::dispatchEvent('salesrule_rule_condition_combine', ['additional' => $additional]);
        if ($additionalConditions = $additional->getConditions()) {
            $conditions = array_merge_recursive($conditions, $additionalConditions);
        }

        return $conditions;
    }
}
