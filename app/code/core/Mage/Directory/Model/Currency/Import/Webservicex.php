<?php

/**
 * Maho
 *
 * @package    Mage_Directory
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Currency rate import model (From www.webservicex.net)
 *
 * @package    Mage_Directory
 * @deprecated after 1.9.4.3
 */
class Mage_Directory_Model_Currency_Import_Webservicex extends Mage_Directory_Model_Currency_Import_Abstract
{
    protected $_url = 'http://www.webservicex.net/CurrencyConvertor.asmx/ConversionRate?FromCurrency={{CURRENCY_FROM}}&ToCurrency={{CURRENCY_TO}}';
    protected $_messages = [];

    /**
     * HTTP client
     *
     * @var Varien_Http_Client
     */
    protected $_httpClient;

    public function __construct()
    {
        $this->_httpClient = new Varien_Http_Client();
    }

    /**
     * @param string $currencyFrom
     * @param string $currencyTo
     * @param int $retry
     * @return float|null
     */
    #[\Override]
    protected function _convert($currencyFrom, $currencyTo, $retry = 0)
    {
        $url = str_replace('{{CURRENCY_FROM}}', $currencyFrom, $this->_url);
        $url = str_replace('{{CURRENCY_TO}}', $currencyTo, $url);

        try {
            $response = $this->_httpClient
                ->setUri($url)
                ->setConfig(['timeout' => Mage::getStoreConfig('currency/webservicex/timeout')])
                ->request('GET')
                ->getBody();

            $xml = simplexml_load_string($response, null, LIBXML_NOERROR);
            if (!$xml) {
                $this->_messages[] = Mage::helper('directory')->__('Cannot retrieve rate from %s.', $url);
                return null;
            }
            return (float) $xml;
        } catch (Exception $e) {
            if ($retry == 0) {
                $this->_convert($currencyFrom, $currencyTo, 1);
            } else {
                $this->_messages[] = Mage::helper('directory')->__('Cannot retrieve rate from %s.', $url);
            }
        }
    }
}
