<?php

/**
 * Maho
 *
 * @package    Varien_Data
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method $this setSize(int $value)
 * @method bool getCanBeEmpty()
 * @method string getSelectAll()
 * @method string getDeselectAll()
 */
class Varien_Data_Form_Element_Multiselect extends Varien_Data_Form_Element_Abstract
{
    /**
     * Varien_Data_Form_Element_Multiselect constructor.
     * @param array $attributes
     */
    public function __construct($attributes = [])
    {
        parent::__construct($attributes);
        $this->setType('select');
        $this->setExtType('multiple');
        $this->setSize(10);
    }

    /**
     * @return string
     */
    #[\Override]
    public function getName()
    {
        $name = parent::getName();
        if (!str_contains($name, '[]')) {
            $name .= '[]';
        }
        return $name;
    }

    /**
     * @return string
     */
    #[\Override]
    public function getElementHtml()
    {
        $this->addClass('select multiselect');
        $html = '';
        if ($this->getCanBeEmpty()) {
            $html .= '<input type="hidden" name="' . parent::getName() . '" value=""';
            $html .= empty($this->_data['disabled']) ? '' : ' disabled="disabled"';
            $html .= '/>';
        }
        $html .= '<select id="' . $this->getHtmlId() . '" name="' . $this->getName() . '" ' .
            $this->serialize($this->getHtmlAttributes()) . ' multiple="multiple">' . "\n";

        $value = $this->getValue();
        if (!is_array($value)) {
            $value = explode(',', (string) $value);
        }

        if ($values = $this->getValues()) {
            foreach ($values as $option) {
                if (is_array($option['value'])) {
                    $html .= '<optgroup label="' . $option['label'] . '">' . "\n";
                    foreach ($option['value'] as $groupItem) {
                        $html .= $this->_optionToHtml($groupItem, $value);
                    }
                    $html .= '</optgroup>' . "\n";
                } else {
                    $html .= $this->_optionToHtml($option, $value);
                }
            }
        }

        $html .= '</select>' . "\n";
        $html .= $this->getAfterElementHtml();

        return $html;
    }

    /**
     * @return array
     */
    #[\Override]
    public function getHtmlAttributes()
    {
        return ['title', 'class', 'style', 'onclick', 'onchange', 'disabled', 'size', 'tabindex'];
    }

    /**
     * @return string
     */
    #[\Override]
    public function getDefaultHtml()
    {
        $result = ($this->getNoSpan() === true) ? '' : '<span class="field-row">' . "\n";
        $result .= $this->getLabelHtml();
        $result .= $this->getElementHtml();

        if ($this->getSelectAll() && $this->getDeselectAll()) {
            $result .= '<a href="#" onclick="return ' . $this->getJsObjectName() . '.selectAll()">' .
                $this->getSelectAll() . '</a> <span class="separator">&nbsp;|&nbsp;</span>';
            $result .= '<a href="#" onclick="return ' . $this->getJsObjectName() . '.deselectAll()">' .
                $this->getDeselectAll() . '</a>';
        }

        $result .= ($this->getNoSpan() === true) ? '' : '</span>' . "\n";

        $result .= '<script type="text/javascript">' . "\n";
        $result .= '   var ' . $this->getJsObjectName() . ' = {' . "\n";
        $result .= '     selectAll: function() { ' . "\n";
        $result .= '         var sel = $("' . $this->getHtmlId() . '");' . "\n";
        $result .= '         for(var i = 0; i < sel.options.length; i ++) { ' . "\n";
        $result .= '             sel.options[i].selected = true; ' . "\n";
        $result .= '         } ' . "\n";
        $result .= '         return false; ' . "\n";
        $result .= '     },' . "\n";
        $result .= '     deselectAll: function() {' . "\n";
        $result .= '         var sel = $("' . $this->getHtmlId() . '");' . "\n";
        $result .= '         for(var i = 0; i < sel.options.length; i ++) { ' . "\n";
        $result .= '             sel.options[i].selected = false; ' . "\n";
        $result .= '         } ' . "\n";
        $result .= '         return false; ' . "\n";
        $result .= '     }' . "\n";
        $result .= '  }' . "\n";
        $result .= "\n" . '</script>';

        return $result;
    }

    /**
     * @return string
     */
    public function getJsObjectName()
    {
        return $this->getHtmlId() . 'ElementControl';
    }

    /**
     * @param array $option
     * @param array $selected
     * @return string
     */
    protected function _optionToHtml($option, $selected)
    {
        $html = '<option value="' . $this->_escape($option['value']) . '"';
        $html .= isset($option['title']) ? 'title="' . $this->_escape($option['title']) . '"' : '';
        $html .= isset($option['style']) ? 'style="' . $option['style'] . '"' : '';
        if (in_array((string) $option['value'], $selected)) {
            $html .= ' selected="selected"';
        }
        $html .= '>' . $this->_escape($option['label']) . '</option>' . "\n";
        return $html;
    }
}
