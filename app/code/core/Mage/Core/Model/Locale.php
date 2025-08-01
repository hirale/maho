<?php

/**
 * Maho
 *
 * @package    Mage_Core
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Core_Model_Locale
{
    /**
     * Default locale name
     */
    public const DEFAULT_LOCALE    = 'en_US';
    public const DEFAULT_TIMEZONE  = 'UTC';
    public const DEFAULT_CURRENCY  = 'USD';

    /**
     * XML path constants
     */
    public const XML_PATH_DEFAULT_LOCALE   = 'general/locale/code';
    public const XML_PATH_DEFAULT_TIMEZONE = 'general/locale/timezone';
    /**
     * @deprecated since 1.4.1.0
     */
    public const XML_PATH_DEFAULT_COUNTRY  = 'general/country/default';
    public const XML_PATH_ALLOW_CODES      = 'global/locale/allow/codes';
    public const XML_PATH_ALLOW_CURRENCIES = 'global/locale/allow/currencies';
    public const XML_PATH_ALLOW_CURRENCIES_INSTALLED = 'system/currency/installed';

    /**
     * Date and time format codes
     */
    public const FORMAT_TYPE_FULL  = 'full';
    public const FORMAT_TYPE_LONG  = 'long';
    public const FORMAT_TYPE_MEDIUM = 'medium';
    public const FORMAT_TYPE_SHORT = 'short';

    /**
     * Default locale code
     *
     * @var string
     */
    protected $_defaultLocale;

    /**
     * Locale object
     *
     * @var Zend_Locale|null
     */
    protected $_locale;

    /**
     * Locale code
     *
     * @var string
     */
    protected $_localeCode;

    /**
     * Emulated locales stack
     *
     * @var array
     */
    protected $_emulatedLocales = [];

    protected static $_currencyCache = [];

    /**
     * Mage_Core_Model_Locale constructor.
     * @param string|null $locale
     */
    public function __construct($locale = null)
    {
        $this->setLocale($locale);
    }

    /**
     * Set default locale code
     *
     * @param   string $locale
     * @return  Mage_Core_Model_Locale
     */
    public function setDefaultLocale($locale)
    {
        $this->_defaultLocale = $locale;
        return $this;
    }

    /**
     * REtrieve default locale code
     *
     * @return string
     */
    public function getDefaultLocale()
    {
        if (!$this->_defaultLocale) {
            $locale = Mage::getStoreConfig(self::XML_PATH_DEFAULT_LOCALE);
            if (!$locale) {
                $locale = self::DEFAULT_LOCALE;
            }
            $this->_defaultLocale = $locale;
        }
        return $this->_defaultLocale;
    }

    /**
     * Set locale
     *
     * @param   string $locale
     * @return  Mage_Core_Model_Locale
     */
    public function setLocale($locale = null)
    {
        if (($locale !== null) && is_string($locale)) {
            $this->_localeCode = $locale;
        } else {
            $this->_localeCode = $this->getDefaultLocale();
        }
        Mage::dispatchEvent('core_locale_set_locale', ['locale' => $this]);
        return $this;
    }

    /**
     * Retrieve timezone code
     *
     * @return string
     */
    public function getTimezone()
    {
        return self::DEFAULT_TIMEZONE;
    }

    /**
     * Retrieve currency code
     *
     * @return string
     */
    public function getCurrency()
    {
        return self::DEFAULT_CURRENCY;
    }

    /**
     * Retrieve locale object
     *
     * @return Zend_Locale
     */
    public function getLocale()
    {
        if (!$this->_locale) {
            //Zend_Locale_Data::setCache(Mage::app()->getCache());
            $this->_locale = new Zend_Locale($this->getLocaleCode());
        } elseif ($this->_locale->__toString() != $this->_localeCode) {
            $this->setLocale($this->_localeCode);
        }

        return $this->_locale;
    }

    /**
     * Retrieve locale code
     *
     * @return string
     */
    public function getLocaleCode()
    {
        if ($this->_localeCode === null) {
            $this->setLocale();
        }
        return $this->_localeCode;
    }

    /**
     * Specify current locale code
     *
     * @param   string $code
     * @return  Mage_Core_Model_Locale
     */
    public function setLocaleCode($code)
    {
        $this->_localeCode = $code;
        $this->_locale = null;
        return $this;
    }

    /**
     * Get options array for locale dropdown in currunt locale
     *
     * @return array
     */
    public function getOptionLocales()
    {
        return $this->_getOptionLocales();
    }

    /**
     * Get translated to original locale options array for locale dropdown
     *
     * @return array
     */
    public function getTranslatedOptionLocales()
    {
        return $this->_getOptionLocales(true);
    }

    /**
     * Get options array for locale dropdown
     *
     * @param   bool $translatedName translation flag
     * @return  array
     */
    protected function _getOptionLocales($translatedName = false)
    {
        $options = [];
        $zendLocales = $this->getLocale()->getLocaleList();
        $languages = $this->getLocale()->getTranslationList('language', $this->getLocale());
        $countries = $this->getCountryTranslationList();

        //Zend locale codes for internal allowed locale codes
        $allowed = $this->getAllowLocales();
        $allowedAliases = [];
        foreach ($allowed as $code) {
            $allowedAliases[Zend_Locale::getAlias($code)] = $code;
        }

        //Internal locale codes translated from Zend locale codes
        $locales = [];
        foreach ($zendLocales as $code => $active) {
            if (array_key_exists($code, $allowedAliases)) {
                $locales[$allowedAliases[$code]] = $active;
            } else {
                $locales[$code] = $active;
            }
        }

        foreach (array_keys($locales) as $code) {
            if (strstr($code, '_')) {
                if (!in_array($code, $allowed)) {
                    continue;
                }
                $data = explode('_', $code);
                if (!isset($languages[$data[0]]) || !isset($countries[$data[1]])) {
                    continue;
                }
                [$language, $country] = $data;
                if ($translatedName) {
                    $translatedLanguage = ucwords($this->getLocale()->getTranslation($language, 'language', $code));
                    $translatedCountry = $this->getCountryTranslation($country, $code);
                    $label = "$translatedLanguage ($translatedCountry) / {$languages[$language]} ({$countries[$country]})";
                } else {
                    $label = "{$languages[$language]} ({$countries[$country]})";
                }
                $options[] = [
                    'value' => $code,
                    'label' => $label,
                ];
            }
        }
        return $this->_sortOptionArray($options);
    }

    /**
     * Retrieve timezone option list
     *
     * @return array
     */
    public function getOptionTimezones()
    {
        $options = [];
        $zones  = $this->getTranslationList('windowstotimezone');
        ksort($zones);
        foreach ($zones as $code => $name) {
            $name = trim($name);
            $zonesList = explode(' ', $code);
            if (count($zonesList) == 1) {
                $options[] = [
                    'label' => empty($name) ? $code : $name . ' (' . $code . ')',
                    'value' => $code,
                ];
            } else {
                foreach ($zonesList as $zoneCode) {
                    $options[] = [
                        'label' => empty($name) ? $zoneCode : $name . ' (' . $zoneCode . ')',
                        'value' => $zoneCode,
                    ];
                }
            }
        }
        return $this->_sortOptionArray($options);
    }

    /**
     * Retrieve days of week option list
     *
     * @param bool $preserveCodes
     * @param bool $ucFirstCode
     *
     * @return array
     */
    public function getOptionWeekdays($preserveCodes = false, $ucFirstCode = false)
    {
        $options = [];
        $days = $this->getTranslationList('days');
        $days = $preserveCodes ? $days['format']['wide'] : array_values($days['format']['wide']);
        foreach ($days as $code => $name) {
            $options[] = [
                'label' => $name,
                'value' => $ucFirstCode ? ucfirst($code) : $code,
            ];
        }
        return $options;
    }

    /**
     * Retrieve country option list
     *
     * @return array
     */
    public function getOptionCountries()
    {
        $options    = [];
        $countries  = $this->getCountryTranslationList();

        foreach ($countries as $code => $name) {
            $options[] = [
                'label' => $name,
                'value' => $code,
            ];
        }
        return $this->_sortOptionArray($options);
    }

    /**
     * Retrieve currency option list
     *
     * @return array
     */
    public function getOptionCurrencies()
    {
        $currencies = $this->getTranslationList('currencytoname');
        $options = [];
        $allowed = $this->getAllowCurrencies();

        foreach ($currencies as $name => $code) {
            if (!in_array($code, $allowed)) {
                continue;
            }

            $options[] = [
                'label' => $name,
                'value' => $code,
            ];
        }
        return $this->_sortOptionArray($options);
    }

    /**
     * Retrieve all currency option list
     *
     * @return array
     */
    public function getOptionAllCurrencies()
    {
        $currencies = $this->getTranslationList('currencytoname');
        $options = [];
        foreach ($currencies as $name => $code) {
            $options[] = [
                'label' => $name,
                'value' => $code,
            ];
        }
        return $this->_sortOptionArray($options);
    }

    /**
     * @param array $option
     * @return array
     */
    protected function _sortOptionArray($option)
    {
        $data = [];
        foreach ($option as $item) {
            $data[$item['value']] = $item['label'];
        }
        asort($data);
        $option = [];
        foreach ($data as $key => $label) {
            $option[] = [
                'value' => $key,
                'label' => $label,
            ];
        }
        return $option;
    }

    /**
     * Retrieve array of allowed locales
     *
     * @return array
     */
    public function getAllowLocales()
    {
        return Mage::getSingleton('core/locale_config')->getAllowedLocales();
    }

    /**
     * Retrieve array of allowed currencies
     *
     * @return array
     */
    public function getAllowCurrencies()
    {
        $data = [];
        if (Mage::isInstalled()) {
            $data = Mage::app()->getStore()->getConfig(self::XML_PATH_ALLOW_CURRENCIES_INSTALLED);
            return explode(',', $data);
        } else {
            $data = Mage::getSingleton('core/locale_config')->getAllowedCurrencies();
        }
        return $data;
    }

    /**
     * Retrieve ISO date format ensuring 4-digit year format
     */
    public function getDateFormat(?string $type = null): string
    {
        $formatter = $this->createDateFormatter($type);
        $pattern = $formatter->getPattern();

        // Convert 2-digit year (yy) to 4-digit year (yyyy) in the pattern
        return $this->ensureFourDigitYear($pattern);
    }

    /**
     * Retrieve short date format with 4-digit year
     */
    public function getDateFormatWithLongYear(): string
    {
        $formatter = $this->createDateFormatter(Mage_Core_Model_Locale::FORMAT_TYPE_SHORT);
        $pattern = $formatter->getPattern();

        // Convert 2-digit year (yy) to 4-digit year (yyyy) in the pattern
        return $this->ensureFourDigitYear($pattern);
    }

    /**
     * Retrieve date format by period type
     * @param string|null $period Valid values: ["day", "month", "year"]
     */
    public function getDateFormatByPeriodType(?string $period = null): string
    {
        $generator = new IntlDatePatternGenerator($this->getLocaleCode());
        return match ($period) {
            'month' => $generator->getBestPattern('yM'),
            'year' => $generator->getBestPattern('y'),
            default => $this->getDateFormat(Mage_Core_Model_Locale::FORMAT_TYPE_MEDIUM),
        };
    }

    /**
     * Create IntlDateFormatter for the current locale
     */
    private function createDateFormatter(?string $type = null): IntlDateFormatter
    {
        $dateStyle = match ($type) {
            Mage_Core_Model_Locale::FORMAT_TYPE_SHORT => IntlDateFormatter::SHORT,
            Mage_Core_Model_Locale::FORMAT_TYPE_MEDIUM => IntlDateFormatter::MEDIUM,
            Mage_Core_Model_Locale::FORMAT_TYPE_LONG => IntlDateFormatter::LONG,
            Mage_Core_Model_Locale::FORMAT_TYPE_FULL => IntlDateFormatter::FULL,
            default => IntlDateFormatter::MEDIUM,
        };

        return new IntlDateFormatter(
            $this->getLocaleCode(),
            $dateStyle,
            IntlDateFormatter::NONE, // No time formatting
            null, // Default timezone
            IntlDateFormatter::GREGORIAN,
        );
    }

    /**
     * Convert 2-digit year patterns (yy) to 4-digit year patterns (yyyy)
     */
    private function ensureFourDigitYear(string $pattern): string
    {
        // This regex is more precise for ICU date patterns
        return preg_replace('/(?<!y)yy(?!y)/', 'yyyy', $pattern);
    }

    /**
     * Retrieve ISO time format
     *
     * @param   string $type
     * @return  string
     */
    public function getTimeFormat($type = null)
    {
        return $this->getTranslation($type, 'time');
    }

    /**
     * Retrieve ISO datetime format
     *
     * @param   string $type
     * @return  string
     */
    public function getDateTimeFormat($type)
    {
        return $this->getDateFormat($type) . ' ' . $this->getTimeFormat($type);
    }

    /**
     * Retrieve date format by strftime function
     *
     * @param   string $type
     * @return  string
     */
    public function getDateStrFormat($type)
    {
        return Varien_Date::convertZendToStrftime($this->getDateFormat($type), true, false);
    }

    /**
     * Retrieve time format by strftime function
     *
     * @param   string $type
     * @return  string
     */
    public function getTimeStrFormat($type)
    {
        return Varien_Date::convertZendToStrftime($this->getTimeFormat($type), false, true);
    }

    /**
     * Create Zend_Date object for current locale
     *
     * @param mixed              $date
     * @param string             $part
     * @param string|Zend_Locale $locale
     * @param bool               $useTimezone
     * @return Zend_Date
     */
    public function date($date = null, $part = null, $locale = null, $useTimezone = true)
    {
        if (is_null($locale)) {
            $locale = $this->getLocale();
        }

        if (!is_int($date) && empty($date)) {
            // $date may be false, but Zend_Date uses strict compare
            $date = null;
        }
        $date = new Zend_Date($date, $part, $locale);
        if ($useTimezone) {
            if ($timezone = Mage::app()->getStore()->getConfig(self::XML_PATH_DEFAULT_TIMEZONE)) {
                $date->setTimezone($timezone);
            }
        }

        return $date;
    }

    /**
     * Create Zend_Date object with date converted to store timezone and store Locale
     *
     * @param   null|string|bool|int|Mage_Core_Model_Store $store Information about store
     * @param   string|int|Zend_Date|array|null $date date in UTC
     * @param   bool $includeTime flag for including time to date
     * @param   string|null $format Format for date parsing/output:
     *                              - null: Use locale default format (returns Zend_Date)
     *                              - 'html5': Return HTML5 native input format (returns string):
     *                                * type="date": YYYY-MM-DD (e.g., "2024-12-25")
     *                                * type="datetime-local": YYYY-MM-DDTHH:mm (e.g., "2024-12-25T14:30")
     *                              - Zend format strings: 'yyyy-MM-dd HH:mm:ss', etc. (returns Zend_Date)
     * @return  Zend_Date|string|null
     */
    public function storeDate($store = null, $date = null, $includeTime = false, $format = null)
    {
        // Special handling for HTML5 format output when format is 'html5'
        if ($format === 'html5') {
            if (empty($date)) {
                return null;
            }

            try {
                $timezone = Mage::app()->getStore($store)->getConfig(self::XML_PATH_DEFAULT_TIMEZONE);
                $dateObj = new Zend_Date($date, null, $this->getLocale());
                $dateObj->setTimezone($timezone);
                if (!$includeTime) {
                    $dateObj->setHour(0)
                        ->setMinute(0)
                        ->setSecond(0);
                }

                if ($includeTime) {
                    return $dateObj->toString('yyyy-MM-dd\'T\'HH:mm');
                } else {
                    return $dateObj->toString('yyyy-MM-dd');
                }
            } catch (Exception $e) {
                return null;
            }
        }

        // Legacy Zend_Date handling
        $timezone = Mage::app()->getStore($store)->getConfig(self::XML_PATH_DEFAULT_TIMEZONE);
        $date = new Zend_Date($date, $format, $this->getLocale());
        $date->setTimezone($timezone);
        if (!$includeTime) {
            $date->setHour(0)
                ->setMinute(0)
                ->setSecond(0);
        }
        return $date;
    }

    /**
     * Create Zend_Date object with date converted from store's timezone
     * to UTC time zone. Date can be passed in format of store's locale
     * or in format which was passed as parameter.
     *
     * @param mixed $store Information about store
     * @param string|int|Zend_Date|array|null $date date in store's timezone
     * @param bool $includeTime flag for including time to date
     * @param null|string $format Format for date parsing/output:
     *                             - null: Use locale default format (returns Zend_Date)
     *                             - 'html5': Parse HTML5 native input format (returns string):
     *                               * Accepts: YYYY-MM-DD (from type="date") or YYYY-MM-DDTHH:mm (from type="datetime-local")
     *                               * Returns: YYYY-MM-DD HH:mm:ss (MySQL datetime format)
     *                             - Zend format strings: 'yyyy-MM-dd HH:mm:ss', etc. (returns Zend_Date)
     *                             - Varien_Date::DATETIME_INTERNAL_FORMAT constant (returns Zend_Date)
     * @return Zend_Date|string|null
     */
    public function utcDate($store, $date, $includeTime = false, $format = null)
    {
        // Special handling for HTML5 native input formats
        if ($format === 'html5' && is_string($date)) {
            if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/', $date)) {
                // datetime-local format - validate the datetime
                $dateTime = DateTime::createFromFormat('Y-m-d\TH:i', substr($date, 0, 16));
                if ($dateTime === false || $dateTime->format('Y-m-d\TH:i') !== substr($date, 0, 16)) {
                    return null;
                }
            } elseif (preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
                // date format - validate the date
                $dateTime = DateTime::createFromFormat('Y-m-d', $date);
                if ($dateTime === false || $dateTime->format('Y-m-d') !== $date) {
                    return null;
                }
                if (!$includeTime) {
                    $dateTime->setTime(0, 0, 0);
                }
            } else {
                return null;
            }

            // Set to store timezone first
            $storeTimezone = Mage::app()->getStore($store)->getConfig(self::XML_PATH_DEFAULT_TIMEZONE);
            $dateTime->setTimezone(new DateTimeZone($storeTimezone));

            // Convert to UTC
            $dateTime->setTimezone(new DateTimeZone('UTC'));

            return $dateTime->format('Y-m-d H:i:s');
        }

        // Legacy Zend_Date handling
        $dateObj = $this->storeDate($store, $date, $includeTime);
        $dateObj->set($date, $format);
        $dateObj->setTimezone(self::DEFAULT_TIMEZONE);
        return $dateObj;
    }

    /**
     * Get store timestamp
     *
     * Timestamp will be built with store timezone settings
     *
     * @param   mixed $store
     * @return  int
     */
    public function storeTimeStamp($store = null)
    {
        $timezone = Mage::app()->getStore($store)->getConfig(self::XML_PATH_DEFAULT_TIMEZONE);
        $currentTimezone = @date_default_timezone_get();
        @date_default_timezone_set($timezone);
        $date = date(Varien_Date::DATETIME_PHP_FORMAT);
        @date_default_timezone_set($currentTimezone);
        return strtotime($date);
    }

    /**
     * Create Zend_Currency object for current locale
     *
     * @param   string $currency
     * @return  Zend_Currency
     */
    public function currency($currency)
    {
        Varien_Profiler::start('locale/currency');
        if (!isset(self::$_currencyCache[$this->getLocaleCode()][$currency])) {
            $options = [];
            try {
                $currencyObject = new Zend_Currency($currency, $this->getLocale());
            } catch (Exception $e) {
                /**
                 * catch specific exceptions like "Currency 'USD' not found"
                 * - back end falls with specific locals as Malaysia and etc.
                 *
                 * as we can see from Zend framework ticket
                 * http://framework.zend.com/issues/browse/ZF-10038
                 * zend team is not going to change it behaviour in the near time
                 */
                $currencyObject = new Zend_Currency($currency);
                $options['name'] = $currency;
                $options['currency'] = $currency;
                $options['symbol'] = $currency;
            }

            $options = new Varien_Object($options);
            Mage::dispatchEvent('currency_display_options_forming', [
                'currency_options' => $options,
                'base_code' => $currency,
            ]);

            $currencyObject->setFormat($options->toArray());
            self::$_currencyCache[$this->getLocaleCode()][$currency] = $currencyObject;
        }
        Varien_Profiler::stop('locale/currency');
        return self::$_currencyCache[$this->getLocaleCode()][$currency];
    }

    /**
     * Returns the first found number from an string
     * Parsing depends on given locale (grouping and decimal)
     *
     * Examples for input:
     * '  2345.4356,1234' = 23455456.1234
     * '+23,3452.123' = 233452.123
     * ' 12343 ' = 12343
     * '-9456km' = -9456
     * '0' = 0
     * '2 054,10' = 2054.1
     * '2'054.52' = 2054.52
     * '2,46 GB' = 2.46
     *
     * @param string|float|int $value
     * @return float|null
     */
    public function getNumber($value)
    {
        if (is_null($value)) {
            return null;
        }

        if (!is_string($value)) {
            return (float) $value;
        }

        //trim spaces and apostrophes
        $value = str_replace(['\'', ' '], '', $value);

        $separatorComa = strpos($value, ',');
        $separatorDot  = strpos($value, '.');

        if ($separatorComa !== false && $separatorDot !== false) {
            if ($separatorComa > $separatorDot) {
                $value = str_replace('.', '', $value);
                $value = str_replace(',', '.', $value);
            } else {
                $value = str_replace(',', '', $value);
            }
        } elseif ($separatorComa !== false) {
            $value = str_replace(',', '.', $value);
        }

        return (float) $value;
    }

    /**
     * Functions returns array with price formatting info for js function
     * formatCurrency in js/varien/js.js
     *
     * @return array
     */
    public function getJsPriceFormat()
    {
        $format = Zend_Locale_Data::getContent($this->getLocaleCode(), 'currencynumber');
        $symbols = Zend_Locale_Data::getList($this->getLocaleCode(), 'symbols');

        $pos = strpos($format, ';');
        if ($pos !== false) {
            $format = substr($format, 0, $pos);
        }
        $format = preg_replace("/[^0\#\.,]/", '', $format);
        $totalPrecision = 0;
        $decimalPoint = strpos($format, '.');
        if ($decimalPoint !== false) {
            $totalPrecision = (strlen($format) - (strrpos($format, '.') + 1));
        } else {
            $decimalPoint = strlen($format);
        }
        $requiredPrecision = $totalPrecision;
        $t = substr($format, $decimalPoint);
        $pos = strpos($t, '#');
        if ($pos !== false) {
            $requiredPrecision = strlen($t) - $pos - $totalPrecision;
        }
        $group = 0;
        if (strrpos($format, ',') !== false) {
            $group = ($decimalPoint - strrpos($format, ',') - 1);
        } else {
            $group = strrpos($format, '.');
        }
        $integerRequired = (strpos($format, '.') - strpos($format, '0'));

        return [
            'pattern' => Mage::app()->getStore()->getCurrentCurrency()->getOutputFormat(),
            'precision' => $totalPrecision,
            'requiredPrecision' => $requiredPrecision,
            'decimalSymbol' => $symbols['decimal'],
            'groupSymbol' => $symbols['group'],
            'groupLength' => $group,
            'integerRequired' => $integerRequired,
        ];
    }

    /**
     * Push current locale to stack and replace with locale from specified store
     * Event is not dispatched.
     *
     * @param int $storeId
     */
    public function emulate($storeId)
    {
        if ($storeId) {
            $this->_emulatedLocales[] = clone $this->getLocale();
            $this->_locale = new Zend_Locale(Mage::getStoreConfig(self::XML_PATH_DEFAULT_LOCALE, $storeId));
            $this->_localeCode = $this->_locale->toString();
            Mage::getSingleton('core/translate')
                ->setLocale($this->_locale)
                ->init(Mage_Core_Model_App_Area::AREA_FRONTEND, true);
        } else {
            $this->_emulatedLocales[] = false;
        }
    }

    /**
     * Get last locale, used before last emulation
     *
     */
    public function revert()
    {
        if ($locale = array_pop($this->_emulatedLocales)) {
            $this->_locale = $locale;
            $this->_localeCode = $this->_locale->toString();
            Mage::getSingleton('core/translate')->setLocale($this->_locale)->init('adminhtml', true);
        }
    }

    /**
     * Returns localized information as array, supported are several
     * types of information.
     * For detailed information about the types look into the documentation
     *
     * @param  string             $path   (Optional) Type of information to return
     * @param  string             $value  (Optional) Value for detail list
     * @return array Array with the wished information in the given language
     */
    public function getTranslationList($path = null, $value = null)
    {
        if ($path === 'country' || $path === 'territory') {
            return $this->getCountryTranslationList();
        }
        return $this->getLocale()->getTranslationList($path, $this->getLocale(), $value);
    }

    /**
     * Returns a localized information string, supported are several types of information.
     * For detailed information about the types look into the documentation
     *
     * @param  string             $value  Name to get detailed information about
     * @param  string             $path   (Optional) Type of information to return
     * @return string|false The wished information in the given language
     */
    public function getTranslation($value = null, $path = null)
    {
        if ($path === 'country' || $path === 'territory') {
            return $this->getCountryTranslation($value);
        }
        return $this->getLocale()->getTranslation($value, $path, $this->getLocale());
    }

    /**
     * Replace all yy date format to yyyy
     *
     * @param string $currentFormat
     * @return string|string[]|null
     */
    protected function _convertYearTwoDigitTo4($currentFormat)
    {
        return preg_replace('/(\byy\b)/', 'yyyy', $currentFormat);
    }

    /**
     * Returns the localized country name
     *
     * @param string $countryId Country to get detailed information about
     * @param string $locale Locale to get translation for, or system locale if null
     * @return false|string
     */
    public function getCountryTranslation($countryId, $locale = null)
    {
        if (!Mage::isInstalled()) {
            // During installation, use native PHP Intl extension for country translation
            return $this->getNativeCountryName($countryId, $locale);
        }

        $country = Mage::getModel('directory/country')->load($countryId);
        if ($country->getId()) {
            if ($locale) {
                $translated = $country->getTranslation($locale);
                if ($translated->getName()) {
                    return $translated->getName();
                }
            }
            return $country->getName();
        }

        return false;
    }

    /**
     * Returns an array with the name of all countries translated to the given language
     *
     * @return array<string, string>
     */
    public function getCountryTranslationList(): array
    {
        if (!Mage::isInstalled()) {
            // During installation, use native PHP Intl extension for country translations
            return $this->getNativeCountryList();
        }

        return Mage::getResourceModel('directory/country_collection')->toOptionHash();
    }

    /**
     * Get native country list using PHP Intl extension (dynamically from ICU data)
     *
     * @return array<string, string>
     */
    protected function getNativeCountryList(): array
    {
        $locale = $this->getLocaleCode();
        $countries = [];
        $countryCodes = [];

        // Dynamically extract country codes from available locales
        $locales = ResourceBundle::getLocales('');
        foreach ($locales as $localeCode) {
            $parsed = Locale::parseLocale($localeCode);
            if (isset($parsed['region']) && strlen($parsed['region']) === 2) {
                $countryCodes[$parsed['region']] = true;
            }
        }

        // Get display names for all discovered country codes
        foreach (array_keys($countryCodes) as $code) {
            try {
                $countryName = Locale::getDisplayRegion('-' . $code, $locale);
                if ($countryName && $countryName !== $code) {
                    $countries[$code] = $countryName;
                } else {
                    // Use country code itself as fallback when translation fails
                    $countries[$code] = $code;
                }
            } catch (IntlException $e) {
                // Use country code itself as fallback for exceptions
                $countries[$code] = $code;
            }
        }

        asort($countries);
        return $countries;
    }

    /**
     * Get native country name using PHP Intl extension
     */
    protected function getNativeCountryName(string $countryId, ?string $locale = null): string
    {
        $displayLocale = $locale ?: $this->getLocaleCode();

        try {
            $countryName = Locale::getDisplayRegion('-' . $countryId, $displayLocale);
            if ($countryName && $countryName !== $countryId) {
                return $countryName;
            } else {
                // Use country code itself as fallback when translation fails
                return $countryId;
            }
        } catch (IntlException $e) {
            // Use country code itself as fallback for exceptions
            return $countryId;
        }
    }

    /**
     * Checks if current date of the given store (in the store timezone) is within the range
     *
     * @param int|string|Mage_Core_Model_Store|null $store
     * @param string|null $dateFrom
     * @param string|null $dateTo
     * @return bool
     */
    public function isStoreDateInInterval($store, $dateFrom = null, $dateTo = null)
    {
        if (!$store instanceof Mage_Core_Model_Store) {
            $store = Mage::app()->getStore($store);
        }

        $storeTimeStamp = $this->storeTimeStamp($store);
        $fromTimeStamp  = strtotime((string) $dateFrom);
        $toTimeStamp    = strtotime((string) $dateTo);
        if ($dateTo) {
            // fix date YYYY-MM-DD 00:00:00 to YYYY-MM-DD 23:59:59
            $toTimeStamp += 86400;
        }

        $result = false;
        if (!is_empty_date((string) $dateFrom) && $storeTimeStamp < $fromTimeStamp) {
        } elseif (!is_empty_date((string) $dateTo) && $storeTimeStamp > $toTimeStamp) {
        } else {
            $result = true;
        }

        return $result;
    }
}
