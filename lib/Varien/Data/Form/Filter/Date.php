<?php

/**
 * Maho
 *
 * @package    Varien_Data
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Varien_Data_Form_Filter_Date implements Varien_Data_Form_Filter_Interface
{
    /**
     * Date format
     *
     * @var string
     */
    protected $_dateFormat;

    /**
     * Local
     *
     * @var string|Zend_Locale
     */
    protected $_locale;

    /**
     * Initialize filter
     *
     * @param string $format    Zend_Date input/output format
     * @param string|Zend_Locale $locale
     */
    public function __construct($format = null, $locale = null)
    {
        if (is_null($format)) {
            $format = Varien_Date::DATE_INTERNAL_FORMAT;
        }
        $this->_dateFormat  = $format;
        $this->_locale      = $locale;
    }

    /**
     * Returns the result of filtering $value
     *
     * @param string|null $value
     * @return string|null
     */
    #[\Override]
    public function inputFilter($value)
    {
        if ($value === null || $value === '') {
            return $value;
        }

        // Check if value is already in ISO format from native date input
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            // Already in correct format (YYYY-MM-DD), return as-is
            return $value;
        }

        $filterInput = new Zend_Filter_LocalizedToNormalized([
            'date_format'   => $this->_dateFormat,
            'locale'        => $this->_locale,
        ]);
        $filterInternal = new Zend_Filter_NormalizedToLocalized([
            'date_format'   => Varien_Date::DATE_INTERNAL_FORMAT,
            'locale'        => $this->_locale,
        ]);

        $value = $filterInput->filter($value);
        $value = $filterInternal->filter($value);
        return $value;
    }

    /**
     * Returns the result of filtering $value
     *
     * @param string|null $value
     * @return string
     */
    #[\Override]
    public function outputFilter($value)
    {
        if ($value === null || $value === '') {
            return $value;
        }

        $filterInput = new Zend_Filter_LocalizedToNormalized([
            'date_format'   => Varien_Date::DATE_INTERNAL_FORMAT,
            'locale'        => $this->_locale,
        ]);
        $filterInternal = new Zend_Filter_NormalizedToLocalized([
            'date_format'   => $this->_dateFormat,
            'locale'        => $this->_locale,
        ]);

        $value = $filterInput->filter($value);
        $value = $filterInternal->filter($value);
        return $value;
    }
}
