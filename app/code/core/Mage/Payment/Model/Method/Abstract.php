<?php

/**
 * Maho
 *
 * @package    Mage_Payment
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method string getCheckoutRedirectUrl()
 * @method $this setInfoInstance(Mage_Payment_Model_Info $value)
 * @method string getInstructions()
 * @method string getOrderPlaceRedirectUrl()
 * @method int getStore()
 * @method $this setStore(int $value)
 * @method $this initBillingAgreementToken(Mage_Sales_Model_Billing_Agreement $value)
 * @method array getBillingAgreementTokenInfo(Mage_Sales_Model_Billing_Agreement $value)
 * @method $this placeBillingAgreement(Mage_Sales_Model_Billing_Agreement $value)
 * @method $this updateBillingAgreementStatus(Mage_Sales_Model_Billing_Agreement $value)
 * @method $this validateRecurringProfile(Mage_Payment_Model_Recurring_Profile $value)
 */
abstract class Mage_Payment_Model_Method_Abstract extends Varien_Object
{
    public const ACTION_ORDER             = 'order';
    public const ACTION_AUTHORIZE         = 'authorize';
    public const ACTION_AUTHORIZE_CAPTURE = 'authorize_capture';

    public const STATUS_UNKNOWN    = 'UNKNOWN';
    public const STATUS_APPROVED   = 'APPROVED';
    public const STATUS_ERROR      = 'ERROR';
    public const STATUS_DECLINED   = 'DECLINED';
    public const STATUS_VOID       = 'VOID';
    public const STATUS_SUCCESS    = 'SUCCESS';

    /**
     * Bit masks to specify different payment method checks.
     * @see Mage_Payment_Model_Method_Abstract::isApplicableToQuote
     */
    public const CHECK_USE_FOR_COUNTRY       = 1;
    public const CHECK_USE_FOR_CURRENCY      = 2;
    public const CHECK_USE_CHECKOUT          = 4;
    public const CHECK_USE_FOR_MULTISHIPPING = 8;
    public const CHECK_USE_INTERNAL          = 16;
    public const CHECK_ORDER_TOTAL_MIN_MAX   = 32;
    public const CHECK_RECURRING_PROFILES    = 64;
    public const CHECK_ZERO_TOTAL            = 128;

    protected $_code;
    protected $_formBlockType = 'payment/form';
    protected $_infoBlockType = 'payment/info';

    /**
     * Payment Method features
     * @var bool
     */
    protected $_isGateway                   = false;
    protected $_canOrder                    = false;
    protected $_canAuthorize                = false;
    protected $_canCapture                  = false;
    protected $_canCapturePartial           = false;
    protected $_canCaptureOnce              = false;
    protected $_canRefund                   = false;
    protected $_canRefundInvoicePartial     = false;
    protected $_canVoid                     = false;
    protected $_canUseInternal              = true;
    protected $_canUseCheckout              = true;
    protected $_canUseForMultishipping      = true;
    protected $_isInitializeNeeded          = false;
    protected $_canFetchTransactionInfo     = false;
    protected $_canReviewPayment            = false;
    protected $_canCreateBillingAgreement   = false;
    protected $_canManageRecurringProfiles  = true;
    /**
     * TODO: whether a captured transaction may be voided by this gateway
     * This may happen when amount is captured, but not settled
     * @var bool
     */
    protected $_canCancelInvoice        = false;

    /**
     * Fields that should be replaced in debug with '***'
     *
     * @var array
     */
    protected $_debugReplacePrivateDataKeys = [];

    public function __construct() {}

    /**
     * Check order availability
     *
     * @return bool
     */
    public function canOrder()
    {
        return $this->_canOrder;
    }

    /**
     * Check authorise availability
     *
     * @return bool
     */
    public function canAuthorize()
    {
        return $this->_canAuthorize;
    }

    /**
     * Check capture availability
     *
     * @return bool
     */
    public function canCapture()
    {
        return $this->_canCapture;
    }

    /**
     * Check partial capture availability
     *
     * @return bool
     */
    public function canCapturePartial()
    {
        return $this->_canCapturePartial;
    }

    /**
     * Check whether capture can be performed once and no further capture possible
     *
     * @return bool
     */
    public function canCaptureOnce()
    {
        return $this->_canCaptureOnce;
    }

    /**
     * Check refund availability
     *
     * @return bool
     */
    public function canRefund()
    {
        return $this->_canRefund;
    }

    /**
     * Check partial refund availability for invoice
     *
     * @return bool
     */
    public function canRefundPartialPerInvoice()
    {
        return $this->_canRefundInvoicePartial;
    }

    /**
     * Check void availability
     *
     * @return  bool
     */
    public function canVoid(Varien_Object $payment)
    {
        return $this->_canVoid;
    }

    /**
     * Using internal pages for input payment data
     * Can be used in admin
     *
     * @return bool
     */
    public function canUseInternal()
    {
        return $this->_canUseInternal;
    }

    /**
     * Can be used in regular checkout
     *
     * @return bool
     */
    public function canUseCheckout()
    {
        return $this->_canUseCheckout;
    }

    /**
     * Using for multiple shipping address
     *
     * @return bool
     */
    public function canUseForMultishipping()
    {
        return $this->_canUseForMultishipping;
    }

    /**
     * Can be edit order (renew order)
     *
     * @return bool
     */
    public function canEdit()
    {
        return true;
    }

    /**
     * Check fetch transaction info availability
     *
     * @return bool
     */
    public function canFetchTransactionInfo()
    {
        return $this->_canFetchTransactionInfo;
    }

    /**
     * Check whether payment method instance can create billing agreements
     *
     * @return bool
     */
    public function canCreateBillingAgreement()
    {
        return $this->_canCreateBillingAgreement;
    }

    /**
     * Fetch transaction info
     *
     * @param string $transactionId
     * @return array
     */
    public function fetchTransactionInfo(Mage_Payment_Model_Info $payment, $transactionId)
    {
        return [];
    }

    /**
     * Retrieve payment system relation flag
     *
     * @return bool
     */
    public function isGateway()
    {
        return $this->_isGateway;
    }

    /**
     * flag if we need to run payment initialize while order place
     *
     * @return bool
     */
    public function isInitializeNeeded()
    {
        return $this->_isInitializeNeeded;
    }

    /**
     * To check billing country is allowed for the payment method
     *
     * @param string $country
     * @return bool
     */
    public function canUseForCountry($country)
    {
        /*
        for specific country, the flag will set up as 1
        */
        if ($this->getConfigData('allowspecific') == 1) {
            $availableCountries = explode(',', $this->getConfigData('specificcountry'));
            if (!in_array($country, $availableCountries)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check method for processing with base currency
     *
     * @param string $currencyCode
     * @return bool
     */
    public function canUseForCurrency($currencyCode)
    {
        return true;
    }

    /**
     * Check manage billing agreements availability
     *
     * @return bool
     */
    public function canManageBillingAgreements()
    {
        return ($this instanceof Mage_Payment_Model_Billing_Agreement_MethodInterface);
    }

    /**
     * Whether can manage recurring profiles
     *
     * @return bool
     */
    public function canManageRecurringProfiles()
    {
        return $this->_canManageRecurringProfiles
               && ($this instanceof Mage_Payment_Model_Recurring_Profile_MethodInterface);
    }

    /**
     * Retrieve model helper
     *
     * @return Mage_Payment_Helper_Data
     */
    protected function _getHelper()
    {
        return Mage::helper('payment');
    }

    /**
     * Retrieve payment method code
     *
     * @return string
     */
    public function getCode()
    {
        if (empty($this->_code)) {
            Mage::throwException(Mage::helper('payment')->__('Cannot retrieve the payment method code.'));
        }
        return $this->_code;
    }

    /**
     * Retrieve block type for method form generation
     *
     * @return string
     */
    public function getFormBlockType()
    {
        return $this->_formBlockType;
    }

    /**
     * Retrieve block type for display method information
     *
     * @return string
     */
    public function getInfoBlockType()
    {
        return $this->_infoBlockType;
    }

    /**
     * Retrieve payment information model object
     *
     * @return Mage_Sales_Model_Order_Payment|Mage_Sales_Model_Quote_Payment
     */
    public function getInfoInstance()
    {
        /** @var Mage_Sales_Model_Order_Payment|Mage_Sales_Model_Quote_Payment $instance */
        $instance = $this->getData('info_instance');
        if (!$instance instanceof Mage_Payment_Model_Info) {
            Mage::throwException(Mage::helper('payment')->__('Cannot retrieve the payment information object instance.'));
        }
        return $instance;
    }

    /**
     * Validate payment method information object
     *
     * @return $this
     */
    public function validate()
    {
        // Validate that payment method is allowed for billing country
        $paymentInfo = $this->getInfoInstance();
        if ($paymentInfo instanceof Mage_Sales_Model_Order_Payment) {
            $billingCountry = $paymentInfo->getOrder()->getBillingAddress()->getCountryId();
        } else {
            $billingCountry = $paymentInfo->getQuote()->getBillingAddress()->getCountryId();
        }
        if (!$this->canUseForCountry($billingCountry)) {
            Mage::throwException(Mage::helper('payment')->__('Selected payment type is not allowed for billing country.'));
        }
        return $this;
    }

    /**
     * Order payment abstract method
     *
     * @param float $amount
     * @return $this
     */
    public function order(Varien_Object $payment, $amount)
    {
        if (!$this->canOrder()) {
            Mage::throwException(Mage::helper('payment')->__('Order action is not available.'));
        }
        return $this;
    }

    /**
     * Authorize payment abstract method
     *
     * @param float $amount
     * @return $this
     */
    public function authorize(Varien_Object $payment, $amount)
    {
        if (!$this->canAuthorize()) {
            Mage::throwException(Mage::helper('payment')->__('Authorize action is not available.'));
        }
        return $this;
    }

    /**
     * Capture payment abstract method
     *
     * @param float $amount
     * @return $this
     */
    public function capture(Varien_Object $payment, $amount)
    {
        if (!$this->canCapture()) {
            Mage::throwException(Mage::helper('payment')->__('Capture action is not available.'));
        }

        return $this;
    }

    /**
     * Set capture transaction ID to invoice for informational purposes
     * @param Mage_Sales_Model_Order_Invoice $invoice
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return Mage_Payment_Model_Method_Abstract
     */
    public function processInvoice($invoice, $payment)
    {
        $invoice->setTransactionId($payment->getLastTransId());
        return $this;
    }

    /**
     * Set refund transaction id to payment object for informational purposes
     * Candidate to be deprecated:
     * there can be multiple refunds per payment, thus payment.refund_transaction_id doesn't make big sense
     *
     * @param Mage_Sales_Model_Order_Invoice $invoice
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return Mage_Payment_Model_Method_Abstract
     */
    public function processBeforeRefund($invoice, $payment)
    {
        $payment->setRefundTransactionId($invoice->getTransactionId());
        return $this;
    }

    /**
     * Refund specified amount for payment
     *
     * @param float $amount
     * @return $this
     */
    public function refund(Varien_Object $payment, $amount)
    {
        if (!$this->canRefund()) {
            Mage::throwException(Mage::helper('payment')->__('Refund action is not available.'));
        }

        return $this;
    }

    /**
     * Set transaction ID into creditmemo for informational purposes
     * @param Mage_Sales_Model_Order_Creditmemo $creditmemo
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return Mage_Payment_Model_Method_Abstract
     */
    public function processCreditmemo($creditmemo, $payment)
    {
        $creditmemo->setTransactionId($payment->getLastTransId());
        return $this;
    }

    /**
     * Cancel payment abstract method
     *
     *
     * @return $this
     */
    public function cancel(Varien_Object $payment)
    {
        return $this;
    }

    /**
     * @deprecated after 1.4.0.0-alpha3
     * this method doesn't make sense, because invoice must not void entire authorization
     * there should be method for invoice cancellation
     * @param Mage_Sales_Model_Order_Invoice $invoice
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return Mage_Payment_Model_Method_Abstract
     */
    public function processBeforeVoid($invoice, $payment)
    {
        $payment->setVoidTransactionId($invoice->getTransactionId());
        return $this;
    }

    /**
     * Void payment abstract method
     *
     *
     * @return $this
     */
    public function void(Varien_Object $payment)
    {
        if (!$this->canVoid($payment)) {
            Mage::throwException(Mage::helper('payment')->__('Void action is not available.'));
        }
        return $this;
    }

    /**
     * Whether this method can accept or deny payment
     *
     *
     * @return bool
     */
    public function canReviewPayment(Mage_Payment_Model_Info $payment)
    {
        return $this->_canReviewPayment;
    }

    /**
     * Attempt to accept a payment that us under review
     *
     * @return bool
     * @throws Mage_Core_Exception
     */
    public function acceptPayment(Mage_Payment_Model_Info $payment)
    {
        if (!$this->canReviewPayment($payment)) {
            Mage::throwException(Mage::helper('payment')->__('The payment review action is unavailable.'));
        }
        return false;
    }

    /**
     * Attempt to deny a payment that us under review
     *
     * @return bool
     * @throws Mage_Core_Exception
     */
    public function denyPayment(Mage_Payment_Model_Info $payment)
    {
        if (!$this->canReviewPayment($payment)) {
            Mage::throwException(Mage::helper('payment')->__('The payment review action is unavailable.'));
        }
        return false;
    }

    /**
     * Retrieve payment method title
     *
     * @return string
     */
    public function getTitle()
    {
        return $this->getConfigData('title');
    }

    /**
     * Retrieve information from payment configuration
     *
     * @param string $field
     * @param int|string|null|Mage_Core_Model_Store $storeId
     *
     * @return mixed
     */
    public function getConfigData($field, $storeId = null)
    {
        if ($storeId === null) {
            $storeId = $this->getStore();
        }
        $path = 'payment/' . $this->getCode() . '/' . $field;
        return Mage::getStoreConfig($path, $storeId);
    }

    /**
     * Assign data to info model instance
     *
     * @param   mixed $data
     * @return  $this
     */
    public function assignData($data)
    {
        if (is_array($data)) {
            $this->getInfoInstance()->addData($data);
        } elseif ($data instanceof Varien_Object) {
            $this->getInfoInstance()->addData($data->getData());
        }
        return $this;
    }

    /**
      * Prepare info instance for save
      *
      * @return $this
      */
    public function prepareSave()
    {
        return $this;
    }

    /**
     * Check whether payment method can be used
     *
     * TODO: payment method instance is not supposed to know about quote
     *
     * @param Mage_Sales_Model_Quote|null $quote
     *
     * @return bool
     */
    public function isAvailable($quote = null)
    {
        $checkResult = new stdClass();
        $isActive = (bool) (int) $this->getConfigData('active', $quote ? $quote->getStoreId() : null);
        $checkResult->isAvailable = $isActive;
        $checkResult->isDeniedInConfig = !$isActive; // for future use in observers

        // Apply payment restrictions
        if ($checkResult->isAvailable) {
            $restrictionModel = Mage::getModel('payment/restriction');
            $customer = null;

            // Get customer if logged in
            if ($quote && $quote->getCustomerId()) {
                $customer = Mage::getModel('customer/customer')->load($quote->getCustomerId());
            }

            $isAllowed = $restrictionModel->validatePaymentMethod(
                $this->getCode(),
                $quote,
                $customer,
            );

            if (!$isAllowed) {
                $checkResult->isAvailable = false;
                $checkResult->isDeniedInConfig = true;
            }
        }

        Mage::dispatchEvent('payment_method_is_active', [
            'result'          => $checkResult,
            'method_instance' => $this,
            'quote'           => $quote,
        ]);

        if ($checkResult->isAvailable && $quote) {
            $checkResult->isAvailable = $this->isApplicableToQuote($quote, self::CHECK_RECURRING_PROFILES);
        }

        return $checkResult->isAvailable;
    }

    /**
     * Check whether payment method is applicable to quote
     * Purposed to allow use in controllers some logic that was implemented in blocks only before
     *
     * @param Mage_Sales_Model_Quote $quote
     * @param int|null $checksBitMask
     * @return bool
     */
    public function isApplicableToQuote($quote, $checksBitMask)
    {
        if ($checksBitMask & self::CHECK_USE_FOR_COUNTRY) {
            if (!$this->canUseForCountry($quote->getBillingAddress()->getCountry())) {
                return false;
            }
        }
        if ($checksBitMask & self::CHECK_USE_FOR_CURRENCY) {
            if (!$this->canUseForCurrency($quote->getStore()->getBaseCurrencyCode())) {
                return false;
            }
        }
        if ($checksBitMask & self::CHECK_USE_CHECKOUT) {
            if (!$this->canUseCheckout()) {
                return false;
            }
        }
        if ($checksBitMask & self::CHECK_USE_FOR_MULTISHIPPING) {
            if (!$this->canUseForMultishipping()) {
                return false;
            }
        }
        if ($checksBitMask & self::CHECK_USE_INTERNAL) {
            if (!$this->canUseInternal()) {
                return false;
            }
        }
        if ($checksBitMask & self::CHECK_ORDER_TOTAL_MIN_MAX) {
            $total = $quote->getBaseGrandTotal();
            $minTotal = $this->getConfigData('min_order_total');
            $maxTotal = $this->getConfigData('max_order_total');
            if (!empty($minTotal) && $total < $minTotal || !empty($maxTotal) && $total > $maxTotal) {
                return false;
            }
        }
        if ($checksBitMask & self::CHECK_RECURRING_PROFILES) {
            if (!$this->canManageRecurringProfiles() && $quote->hasRecurringItems()) {
                return false;
            }
        }
        if ($checksBitMask & self::CHECK_ZERO_TOTAL) {
            $total = $quote->getBaseSubtotal() + $quote->getShippingAddress()->getBaseShippingAmount();
            if ($total < 0.0001 && $this->getCode() != 'free'
                && !($this->canManageRecurringProfiles() && $quote->hasRecurringItems())
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * Method that will be executed instead of authorize or capture
     * if flag isInitializeNeeded set to true
     *
     * @param string $paymentAction
     * @param object $stateObject
     *
     * @return $this
     */
    public function initialize($paymentAction, $stateObject)
    {
        return $this;
    }

    /**
     * Get config payment action url
     * Used to universalize payment actions when processing payment place
     *
     * @return string
     */
    public function getConfigPaymentAction()
    {
        return $this->getConfigData('payment_action');
    }

    /**
     * Log debug data to file
     *
     * @param mixed $debugData
     */
    protected function _debug($debugData)
    {
        if ($this->getDebugFlag()) {
            Mage::getModel('core/log_adapter', 'payment_' . $this->getCode() . '.log')
               ->setFilterDataKeys($this->_debugReplacePrivateDataKeys)
               ->log($debugData);
        }
    }

    /**
     * Define if debugging is enabled
     *
     * @return bool
     */
    public function getDebugFlag()
    {
        return $this->getConfigData('debug');
    }

    /**
     * Used to call debug method from not Payment Method context
     *
     * @param mixed $debugData
     */
    public function debugData($debugData)
    {
        $this->_debug($debugData);
    }
}
