<?php

/**
 * Maho
 *
 * @package    Varien_Data
 * @copyright  Copyright (c) 2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Varien_Data_Form_Element_Info extends Varien_Data_Form_Element_Abstract
{
    /**
     * @param array $attributes
     */
    public function __construct($attributes = [])
    {
        parent::__construct($attributes);
        $this
            ->setType('info')
            ->unsScope()
            ->unsCanUseDefaultValue()
            ->unsCanUseWebsiteValue();
    }

    /**
     * @return string
     */
    #[\Override]
    public function getHtml()
    {
        $id = $this->getHtmlId();
        $label = $this->getLabel();
        $html = '<tr class="' . $id . '"><td class="label" colspan="99"><label>' . $label . '</label></td></tr>';
        return $html;
    }
}
