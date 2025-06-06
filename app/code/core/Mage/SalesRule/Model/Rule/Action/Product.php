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

class Mage_SalesRule_Model_Rule_Action_Product extends Mage_Rule_Model_Action_Abstract
{
    /**
     * @return $this|Mage_Rule_Model_Action_Abstract
     */
    #[\Override]
    public function loadAttributeOptions()
    {
        $this->setAttributeOption([
            'rule_price' => Mage::helper('salesrule')->__('Special Price'),
        ]);
        return $this;
    }

    /**
     * @return $this|Mage_Rule_Model_Action_Abstract
     */
    #[\Override]
    public function loadOperatorOptions()
    {
        $this->setOperatorOption([
            'to_fixed'   => static::$translate ? Mage::helper('salesrule')->__('To Fixed Value') : 'To Fixed Value',
            'to_percent' => static::$translate ? Mage::helper('salesrule')->__('To Percentage') : 'To Percentage',
            'by_fixed'   => static::$translate ? Mage::helper('salesrule')->__('By Fixed value') : 'By Fixed value',
            'by_percent' => static::$translate ? Mage::helper('salesrule')->__('By Percentage') : 'By Percentage',
        ]);
        return $this;
    }

    /**
     * @return string
     */
    #[\Override]
    public function asHtml()
    {
        $html = $this->getTypeElement()->getHtml() . Mage::helper('salesrule')->__("Update product's %s %s: %s", $this->getAttributeElement()->getHtml(), $this->getOperatorElement()->getHtml(), $this->getValueElement()->getHtml());
        $html .= $this->getRemoveLinkHtml();
        return $html;
    }
}
