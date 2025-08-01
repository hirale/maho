<?php

/**
 * Maho
 *
 * @package    Mage_Paypal
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Paypal_Model_Payflowpro extends Mage_Payment_Model_Method_Cc
{
    /**
     * Transaction action codes
     */
    public const TRXTYPE_AUTH_ONLY         = 'A';
    public const TRXTYPE_SALE              = 'S';
    public const TRXTYPE_CREDIT            = 'C';
    public const TRXTYPE_DELAYED_CAPTURE   = 'D';
    public const TRXTYPE_DELAYED_VOID      = 'V';
    public const TRXTYPE_DELAYED_VOICE     = 'F';
    public const TRXTYPE_DELAYED_INQUIRY   = 'I';

    /**
     * Tender type codes
     */
    public const TENDER_CC = 'C';

    /**
     * Gateway request URLs
     */
    public const TRANSACTION_URL           = 'https://payflowpro.paypal.com/transaction';
    public const TRANSACTION_URL_TEST_MODE = 'https://pilot-payflowpro.paypal.com/transaction';

    /**
     * Response codes
     */
    public const RESPONSE_CODE_APPROVED                = 0;
    public const RESPONSE_CODE_INVALID_AMOUNT          = 4;
    public const RESPONSE_CODE_FRAUDSERVICE_FILTER     = 126;
    public const RESPONSE_CODE_DECLINED                = 12;
    public const RESPONSE_CODE_DECLINED_BY_FILTER      = 125;
    public const RESPONSE_CODE_DECLINED_BY_MERCHANT    = 128;
    public const RESPONSE_CODE_CAPTURE_ERROR           = 111;
    public const RESPONSE_CODE_VOID_ERROR              = 108;

    /**
     * Payment method code
     */
    protected $_code = Mage_Paypal_Model_Config::METHOD_PAYFLOWPRO;

    /**
     * Availability options
     */
    protected $_isGateway               = true;
    protected $_canAuthorize            = true;
    protected $_canCapture              = true;
    protected $_canCapturePartial       = true;
    protected $_canRefund               = true;
    protected $_canRefundInvoicePartial = true;
    protected $_canVoid                 = true;
    protected $_canUseInternal          = true;
    protected $_canUseCheckout          = true;
    protected $_canUseForMultishipping  = true;
    protected $_canSaveCc = false;
    protected $_isProxy = false;
    protected $_canFetchTransactionInfo = true;

    /**
     * Gateway request timeout
     */
    protected $_clientTimeout = 45;

    /**
     * Fields that should be replaced in debug with '***'
     *
     * @var array
     */
    protected $_debugReplacePrivateDataKeys = ['user', 'pwd', 'acct', 'expdate', 'cvv2'];

    /**
     * Centinel cardinal fields map
     *
     * @var string
     */
    protected $_centinelFieldMap = [
        'centinel_mpivendor'    => 'MPIVENDOR3DS',
        'centinel_authstatus'   => 'AUTHSTATUS3DS',
        'centinel_cavv'         => 'CAVV',
        'centinel_eci'          => 'ECI',
        'centinel_xid'          => 'XID',
    ];

    /**
     * Check whether payment method can be used
     *
     * @param Mage_Sales_Model_Quote|null $quote
     * @return bool
     */
    #[\Override]
    public function isAvailable($quote = null)
    {
        $storeId = Mage::app()->getStore($this->getStore())->getId();
        $config = Mage::getModel('paypal/config')->setStoreId($storeId);
        if (parent::isAvailable($quote) && $config->isMethodAvailable($this->getCode())) {
            return true;
        }
        return false;
    }

    /**
     * Payment action getter compatible with payment model
     *
     * @see Mage_Sales_Model_Payment::place()
     * @return string
     */
    #[\Override]
    public function getConfigPaymentAction()
    {
        return match ($this->getConfigData('payment_action')) {
            Mage_Paypal_Model_Config::PAYMENT_ACTION_AUTH => Mage_Payment_Model_Method_Abstract::ACTION_AUTHORIZE,
            Mage_Paypal_Model_Config::PAYMENT_ACTION_SALE => Mage_Payment_Model_Method_Abstract::ACTION_AUTHORIZE_CAPTURE,
            default => '',
        };
    }

    /**
     * Authorize payment
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return $this
     */
    #[\Override]
    public function authorize(Varien_Object $payment, $amount)
    {
        $request = $this->_buildPlaceRequest($payment, $amount);
        $request->setTrxtype(self::TRXTYPE_AUTH_ONLY);
        $this->_setReferenceTransaction($payment, $request);
        $response = $this->_postRequest($request);
        $this->_processErrors($response);

        switch ($response->getResultCode()) {
            case self::RESPONSE_CODE_APPROVED:
                $payment->setTransactionId($response->getPnref())->setIsTransactionClosed(0);
                break;
            case self::RESPONSE_CODE_FRAUDSERVICE_FILTER:
                $payment->setTransactionId($response->getPnref())->setIsTransactionClosed(0);
                $payment->setIsTransactionPending(true);
                $payment->setIsFraudDetected(true);
                break;
        }
        return $this;
    }

    /**
     * Get capture amount
     *
     * @param float $amount
     * @return float
     */
    protected function _getCaptureAmount($amount)
    {
        $infoInstance = $this->getInfoInstance();
        $amountToPay = round($amount, 2);
        $authorizedAmount = round($infoInstance->getAmountAuthorized(), 2);
        return $amountToPay != $authorizedAmount ? $amountToPay : 0;
    }

    /**
     * Capture payment
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return $this
     */
    #[\Override]
    public function capture(Varien_Object $payment, $amount)
    {
        if ($payment->getReferenceTransactionId()) {
            $request = $this->_buildPlaceRequest($payment, $amount);
            $request->setTrxtype(self::TRXTYPE_SALE);
            $request->setOrigid($payment->getReferenceTransactionId());
        } elseif ($payment->getParentTransactionId()) {
            $request = $this->_buildBasicRequest($payment);
            $request->setOrigid($payment->getParentTransactionId());
            $captureAmount = $this->_getCaptureAmount($amount);
            if ($captureAmount) {
                $request->setAmt($captureAmount);
            }
            $trxType = $this->getInfoInstance()->hasAmountPaid() ? self::TRXTYPE_SALE : self::TRXTYPE_DELAYED_CAPTURE;
            $request->setTrxtype($trxType);
        } else {
            $request = $this->_buildPlaceRequest($payment, $amount);
            $request->setTrxtype(self::TRXTYPE_SALE);
        }

        $response = $this->_postRequest($request);
        $this->_processErrors($response);

        switch ($response->getResultCode()) {
            case self::RESPONSE_CODE_APPROVED:
                $payment->setTransactionId($response->getPnref())->setIsTransactionClosed(0);
                break;
            case self::RESPONSE_CODE_FRAUDSERVICE_FILTER:
                $payment->setTransactionId($response->getPnref())->setIsTransactionClosed(0);
                $payment->setIsTransactionPending(true);
                $payment->setIsFraudDetected(true);
                break;
        }
        return $this;
    }

    /**
     * Void payment
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return $this
     */
    #[\Override]
    public function void(Varien_Object $payment)
    {
        $request = $this->_buildBasicRequest($payment);
        $request->setTrxtype(self::TRXTYPE_DELAYED_VOID);
        $request->setOrigid($payment->getParentTransactionId());
        $response = $this->_postRequest($request);
        $this->_processErrors($response);

        if ($response->getResultCode() == self::RESPONSE_CODE_APPROVED) {
            $payment->setTransactionId($response->getPnref())
                ->setIsTransactionClosed(1)
                ->setShouldCloseParentTransaction(1);
        }

        return $this;
    }

    /**
     * Check void availability
     *
     * @return  bool
     */
    #[\Override]
    public function canVoid(Varien_Object $payment)
    {
        if ($payment instanceof Mage_Sales_Model_Order_Invoice
            || $payment instanceof Mage_Sales_Model_Order_Creditmemo
        ) {
            return false;
        }
        if ($payment->getAmountPaid()) {
            $this->_canVoid = false;
        }

        return $this->_canVoid;
    }

    /**
     * Attempt to void the authorization on cancelling
     *
     * @return $this|false
     */
    #[\Override]
    public function cancel(Varien_Object $payment)
    {
        if (!$payment->getOrder()->getInvoiceCollection()->count()) {
            return $this->void($payment);
        }

        return false;
    }

    /**
     * Refund capture
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return $this
     */
    #[\Override]
    public function refund(Varien_Object $payment, $amount)
    {
        $request = $this->_buildBasicRequest($payment);
        $request->setTrxtype(self::TRXTYPE_CREDIT);
        $request->setOrigid($payment->getParentTransactionId());
        $request->setAmt(round((float) $amount, 2));
        $response = $this->_postRequest($request);
        $this->_processErrors($response);

        if ($response->getResultCode() == self::RESPONSE_CODE_APPROVED) {
            $payment->setTransactionId($response->getPnref())
                ->setIsTransactionClosed(1);
            $payment->setShouldCloseParentTransaction(!$payment->getCreditmemo()->getInvoice()->canRefund());
        }
        return $this;
    }

    /**
     * Fetch transaction details info
     *
     * @param string $transactionId
     * @return array
     */
    #[\Override]
    public function fetchTransactionInfo(Mage_Payment_Model_Info $payment, $transactionId)
    {
        $request = $this->_buildBasicRequest($payment);
        $request->setTrxtype(self::TRXTYPE_DELAYED_INQUIRY);
        $request->setOrigid($transactionId);
        $response = $this->_postRequest($request);

        $this->_processErrors($response);

        if (!self::_isTransactionUnderReview($response->getOrigresult())) {
            $payment->setTransactionId($response->getOrigpnref())
                ->setIsTransactionClosed(0);
            if ($response->getOrigresult() == self::RESPONSE_CODE_APPROVED) {
                $payment->setIsTransactionApproved(true);
            } elseif ($response->getOrigresult() == self::RESPONSE_CODE_DECLINED_BY_MERCHANT) {
                $payment->setIsTransactionDenied(true);
            }
        }

        $rawData = $response->getData();
        return $rawData ?: [];
    }

    /**
     * Check whether the transaction is in payment review status
     *
     * @param string $status
     * @return bool
     */
    protected static function _isTransactionUnderReview($status)
    {
        if (in_array($status, [self::RESPONSE_CODE_APPROVED, self::RESPONSE_CODE_DECLINED_BY_MERCHANT])) {
            return false;
        }
        return true;
    }

    /**
     * Getter for URL to perform Payflow requests, based on test mode by default
     *
     * @param bool $testMode Ability to specify test mode using
     * @return string
     */
    protected function _getTransactionUrl($testMode = null)
    {
        $testMode = is_null($testMode) ? $this->getConfigData('sandbox_flag') : (bool) $testMode;
        if ($testMode) {
            return self::TRANSACTION_URL_TEST_MODE;
        }
        return self::TRANSACTION_URL;
    }

    /**
     * Post request to gateway and return response
     *
     * @return Varien_Object
     */
    protected function _postRequest(Varien_Object $request)
    {
        $debugData = ['request' => $request->getData()];

        $result = new Varien_Object();

        $_config = [
            'max_redirects' => 5,
            'timeout'    => 30,
            'verify_peer' => $this->getConfigData('verify_peer'),
        ];

        //checking proxy
        $_isProxy = $this->getConfigData('use_proxy', false);
        if ($_isProxy) {
            $_config['proxy'] = $this->getConfigData('proxy_host')
                . ':'
                . $this->getConfigData('proxy_port');
        }

        $client = \Symfony\Component\HttpClient\HttpClient::create($_config);

        $headers = [
            'X-VPS-VIT-CLIENT-CERTIFICATION-ID' => '33baf5893fc2123d8b191d2d011b7fdc',
            'X-VPS-Request-ID' => $request->getRequestId(),
            'X-VPS-CLIENT-TIMEOUT' => $this->_clientTimeout,
        ];

        try {
            /**
             * we are sending request to payflow pro without url encoding
             * so we build the query string manually
             */
            $requestData = $request->getData();
            $queryString = http_build_query($requestData, '', '&', PHP_QUERY_RFC3986);
            $queryString = urldecode($queryString);

            $response = $client->request('POST', $this->_getTransactionUrl(), [
                'headers' => $headers,
                'body' => $queryString,
            ]);
        } catch (Exception $e) {
            $result->setResponseCode(-1)
                ->setResponseReasonCode($e->getCode())
                ->setResponseReasonText($e->getMessage());

            $debugData['result'] = $result->getData();
            $this->_debug($debugData);
            throw $e;
        }

        $responseBody = $response->getContent();
        $response = strstr($responseBody, 'RESULT');
        $valArray = explode('&', $response);

        foreach ($valArray as $val) {
            $valArray2 = explode('=', $val);
            $result->setData(strtolower($valArray2[0]), $valArray2[1]);
        }

        $result->setResultCode($result->getResult())
                ->setRespmsg($result->getRespmsg());

        $debugData['result'] = $result->getData();
        $this->_debug($debugData);

        return $result;
    }

    /**
     * Return request object with information for 'authorization' or 'sale' action
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param float $amount
     * @return Varien_Object
     */
    protected function _buildPlaceRequest(Varien_Object $payment, $amount)
    {
        $request = $this->_buildBasicRequest($payment);
        $request->setAmt(round($amount, 2));
        $request->setAcct($payment->getCcNumber());
        $request->setExpdate(sprintf('%02d', $payment->getCcExpMonth()) . substr($payment->getCcExpYear(), -2, 2));
        $request->setCvv2($payment->getCcCid());

        $order = $payment->getOrder();
        if (!empty($order)) {
            $orderIncrementId = $order->getIncrementId();

            $request->setCurrency($order->getBaseCurrencyCode())
                ->setInvnum($orderIncrementId)
                ->setPonum($order->getId())
                ->setComment1($orderIncrementId);

            $customerId = $order->getCustomerId();
            if ($customerId) {
                $request->setCustref($customerId);
            }

            $billing = $order->getBillingAddress();
            if (!empty($billing)) {
                $request->setFirstname($billing->getFirstname())
                    ->setLastname($billing->getLastname())
                    ->setStreet(implode(' ', $billing->getStreet()))
                    ->setCity($billing->getCity())
                    ->setState($billing->getRegionCode())
                    ->setZip($billing->getPostcode())
                    ->setCountry($billing->getCountry())
                    ->setEmail($payment->getOrder()->getCustomerEmail());
            }
            $shipping = $order->getShippingAddress();
            if (!empty($shipping)) {
                $this->_applyCountryWorkarounds($shipping);
                $request->setShiptofirstname($shipping->getFirstname())
                    ->setShiptolastname($shipping->getLastname())
                    ->setShiptostreet(implode(' ', $shipping->getStreet()))
                    ->setShiptocity($shipping->getCity())
                    ->setShiptostate($shipping->getRegionCode())
                    ->setShiptozip($shipping->getPostcode())
                    ->setShiptocountry($shipping->getCountry());
            }
        }
        return $request;
    }

    /**
     * Return request object with basic information for gateway request
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return Varien_Object
     */
    protected function _buildBasicRequest(Varien_Object $payment)
    {
        $request = new Varien_Object();
        $bnCode = Mage::getModel('paypal/config')->getBuildNotationCode();
        $request
            ->setUser($this->getConfigData('user'))
            ->setVendor($this->getConfigData('vendor'))
            ->setPartner($this->getConfigData('partner'))
            ->setPwd($this->getConfigData('pwd'))
            ->setVerbosity($this->getConfigData('verbosity'))
            ->setData('BNCODE', $bnCode)
            ->setTender(self::TENDER_CC)
            ->setRequestId($this->_generateRequestId());
        return $request;
    }

    /**
     * Return unique value for request
     *
     * @return string
     */
    protected function _generateRequestId()
    {
        return Mage::helper('core')->uniqHash();
    }

    /**
     * If response is failed throw exception
     *
     * @throws Mage_Core_Exception
     */
    protected function _processErrors(Varien_Object $response)
    {
        if ($response->getResultCode() == self::RESPONSE_CODE_VOID_ERROR) {
            throw new Mage_Paypal_Exception(Mage::helper('paypal')->__('You cannot void a verification transaction'));
        } elseif ($response->getResultCode() != self::RESPONSE_CODE_APPROVED
            && $response->getResultCode() != self::RESPONSE_CODE_FRAUDSERVICE_FILTER
        ) {
            Mage::throwException($response->getRespmsg());
        }
    }

    /**
     * Adopt specified address object to be compatible with Paypal
     * Puerto Rico should be as state of USA and not as a country
     */
    protected function _applyCountryWorkarounds(Varien_Object $address)
    {
        if ($address->getCountry() == 'PR') {
            $address->setCountry('US');
            $address->setRegionCode('PR');
        }
    }

    /**
     * Set reference transaction data into request
     *
     * @param Varien_Object $request
     * @return $this
     */
    protected function _setReferenceTransaction(Varien_Object $payment, $request)
    {
        return $this;
    }
}
