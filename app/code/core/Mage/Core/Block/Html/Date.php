<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2017-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method string getClass()
 * @method $this setClass(string $value)
 * @method string getExtraParams()
 * @method $this setExtraParams(string $value)
 * @method string getFormat()
 * @method $this setFormat(string $value)
 * @method string getName()
 * @method $this setName(string $value)
 * @method string getTime()
 * @method $this setTime(string $value)
 * @method $this setTitle(string $value)
 * @method string getValue()
 * @method $this setValue(string $value)
 * @method string getYearsRange()
 * @method $this setYearsRange(string $value)
 */
class Mage_Core_Block_Html_Date extends Mage_Core_Block_Template
{
    /**
     * @return string
     */
    #[\Override]
    protected function _toHtml()
    {
        $displayFormat = Varien_Date::convertZendToStrftime($this->getFormat(), true, (bool) $this->getTime());

        $html  = '<input type="text" name="' . $this->getName() . '" id="' . $this->getId() . '" ';
        $html .= 'value="' . $this->escapeHtml($this->getValue()) . '" class="' . $this->getClass() . '" ' . $this->getExtraParams() . '/> ';

        $html .=
        '<script type="text/javascript">
            var calendarSetupObject = {
                inputField  : "' . $this->getId() . '",
                ifFormat    : "' . $displayFormat . '",
                showsTime   : ' . ($this->getTime() ? 'true' : 'false') . '
            }';

        $calendarYearsRange = $this->getYearsRange();
        if ($calendarYearsRange) {
            $html .= '
                calendarSetupObject.range = ' . $calendarYearsRange . '
                ';
        }

        $html .= '
            Calendar.setup(calendarSetupObject);
        </script>';

        return $html;
    }

    /**
     * @param null $index deprecated
     * @return string
     */
    public function getEscapedValue($index = null)
    {
        if ($this->getFormat() && $this->getValue()) {
            return date($this->getFormat(), strtotime($this->getValue()));
        }

        return htmlspecialchars($this->getValue());
    }

    /**
     * @return string
     */
    public function getHtml()
    {
        return $this->toHtml();
    }
}
