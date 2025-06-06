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

class Mage_Adminhtml_Block_Widget_Grid_Column_Filter_Store extends Mage_Adminhtml_Block_Widget_Grid_Column_Filter_Abstract
{
    /**
     * Render HTML of the element
     *
     * @return string
     */
    #[\Override]
    public function getHtml()
    {
        $storeModel = Mage::getSingleton('adminhtml/system_store');
        /** @var Mage_Adminhtml_Model_System_Store $storeModel */
        $websiteCollection = $storeModel->getWebsiteCollection();
        $groupCollection = $storeModel->getGroupCollection();
        $storeCollection = $storeModel->getStoreCollection();

        $allShow = $this->getColumn()->getStoreAll();

        $html  = '<select name="' . $this->escapeHtml($this->_getHtmlName()) . '" '
               . $this->getColumn()->getValidateClass() . '>';
        $value = $this->getColumn()->getValue();
        if ($allShow) {
            $html .= '<option value="0"' . ($value == 0 ? ' selected="selected"' : '') . '>'
                  . Mage::helper('adminhtml')->__('All Store Views') . '</option>';
        } else {
            $html .= '<option value=""' . (!$value ? ' selected="selected"' : '') . '></option>';
        }
        foreach ($websiteCollection as $website) {
            $websiteShow = false;
            foreach ($groupCollection as $group) {
                if ($group->getWebsiteId() != $website->getId()) {
                    continue;
                }
                $groupShow = false;
                foreach ($storeCollection as $store) {
                    if ($store->getGroupId() != $group->getId()) {
                        continue;
                    }
                    if (!$websiteShow) {
                        $websiteShow = true;
                        $html .= '<optgroup label="' . $this->escapeHtml($website->getName()) . '"></optgroup>';
                    }
                    if (!$groupShow) {
                        $groupShow = true;
                        $html .= '<optgroup label="&nbsp;&nbsp;&nbsp;&nbsp;'
                              . $this->escapeHtml($group->getName()) . '">';
                    }
                    $value = $this->getValue();
                    $selected = $value == $store->getId() ? ' selected="selected"' : '';
                    $html .= '<option value="' . $store->getId() . '"' . $selected . '>&nbsp;&nbsp;&nbsp;&nbsp;'
                          . $this->escapeHtml($store->getName()) . '</option>';
                }
                if ($groupShow) {
                    $html .= '</optgroup>';
                }
            }
        }
        if ($this->getColumn()->getDisplayDeleted()) {
            $selected = ($this->getValue() == '_deleted_') ? ' selected' : '';
            $html .= '<option value="_deleted_"' . $selected . '>' . $this->__('[ deleted ]') . '</option>';
        }
        $html .= '</select>';
        return $html;
    }

    /**
     * Form condition from element's value
     *
     * @return array|null
     */
    #[\Override]
    public function getCondition()
    {
        if (is_null($this->getValue())) {
            return null;
        }
        if ($this->getValue() == '_deleted_') {
            return ['null' => true];
        } else {
            return ['eq' => $this->getValue()];
        }
    }
}
