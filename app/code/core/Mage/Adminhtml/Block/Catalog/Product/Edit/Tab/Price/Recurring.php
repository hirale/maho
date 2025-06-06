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

class Mage_Adminhtml_Block_Catalog_Product_Edit_Tab_Price_Recurring extends Mage_Adminhtml_Block_Catalog_Form_Renderer_Fieldset_Element
{
    /**
     * Element output getter
     *
     * @return string
     */
    #[\Override]
    public function getElementHtml()
    {
        $result = new stdClass();
        $result->output = '';
        Mage::dispatchEvent('catalog_product_edit_form_render_recurring', [
            'result' => $result,
            'product_element' => $this->_element,
            'product'   => Mage::registry('current_product'),
        ]);
        return $result->output;
    }
}
