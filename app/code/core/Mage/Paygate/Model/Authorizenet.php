<?php

/**
 * Maho
 *
 * @package    Mage_Paygate
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Paygate_Model_Authorizenet extends Mage_Payment_Model_Method_Cc
{
    /**
     * AIM gateway url
     */
    public const CGI_URL = 'https://secure.authorize.net/gateway/transact.dll';

    /**
     * Transaction Details gateway url
     */
    public const CGI_URL_TD = 'https://api.authorize.net/xml/v1/request.api';

    public const REQUEST_METHOD_CC     = 'CC';
    public const REQUEST_METHOD_ECHECK = 'ECHECK';

    public const REQUEST_TYPE_AUTH_CAPTURE = 'AUTH_CAPTURE';
    public const REQUEST_TYPE_AUTH_ONLY    = 'AUTH_ONLY';
    public const REQUEST_TYPE_CAPTURE_ONLY = 'CAPTURE_ONLY';
    public const REQUEST_TYPE_CREDIT       = 'CREDIT';
    public const REQUEST_TYPE_VOID         = 'VOID';
    public const REQUEST_TYPE_PRIOR_AUTH_CAPTURE = 'PRIOR_AUTH_CAPTURE';

    public const ECHECK_ACCT_TYPE_CHECKING = 'CHECKING';
    public const ECHECK_ACCT_TYPE_BUSINESS = 'BUSINESSCHECKING';
    public const ECHECK_ACCT_TYPE_SAVINGS  = 'SAVINGS';

    public const ECHECK_TRANS_TYPE_CCD = 'CCD';
    public const ECHECK_TRANS_TYPE_PPD = 'PPD';
    public const ECHECK_TRANS_TYPE_TEL = 'TEL';
    public const ECHECK_TRANS_TYPE_WEB = 'WEB';

    public const RESPONSE_DELIM_CHAR = '(~)';

    public const RESPONSE_CODE_APPROVED = 1;
    public const RESPONSE_CODE_DECLINED = 2;
    public const RESPONSE_CODE_ERROR    = 3;
    public const RESPONSE_CODE_HELD     = 4;

    public const RESPONSE_REASON_CODE_APPROVED = 1;
    public const RESPONSE_REASON_CODE_NOT_FOUND = 16;
    public const RESPONSE_REASON_CODE_PARTIAL_APPROVE = 295;
    public const RESPONSE_REASON_CODE_PENDING_REVIEW_AUTHORIZED = 252;
    public const RESPONSE_REASON_CODE_PENDING_REVIEW = 253;
    public const RESPONSE_REASON_CODE_PENDING_REVIEW_DECLINED = 254;

    public const PARTIAL_AUTH_CARDS_LIMIT = 5;

    public const PARTIAL_AUTH_LAST_SUCCESS         = 'last_success';
    public const PARTIAL_AUTH_LAST_DECLINED        = 'last_declined';
    public const PARTIAL_AUTH_ALL_CANCELED         = 'all_canceled';
    public const PARTIAL_AUTH_CARDS_LIMIT_EXCEEDED = 'card_limit_exceeded';
    public const PARTIAL_AUTH_DATA_CHANGED         = 'data_changed';

    public const METHOD_CODE = 'authorizenet';

    public const TRANSACTION_STATUS_EXPIRED = 'expired';

    protected $_code  = self::METHOD_CODE;

    /**
     * Form block type
     */
    protected $_formBlockType = 'paygate/authorizenet_form_cc';

    /**
     * Info block type
     */
    protected $_infoBlockType = 'paygate/authorizenet_info_cc';

    /**
     * Availability options
     */
    protected $_isGateway               = true;
    protected $_canAuthorize            = true;
    protected $_canCapture              = true;
    protected $_canCapturePartial       = false;
    protected $_canRefund               = true;
    protected $_canRefundInvoicePartial = true;
    protected $_canVoid                 = true;
    protected $_canUseInternal          = true;
    protected $_canUseCheckout          = true;
    protected $_canUseForMultishipping  = true;
    protected $_canSaveCc               = false;
    protected $_canFetchTransactionInfo = true;

    protected $_allowCurrencyCode = ['USD'];

    /**
     * @var Mage_Paygate_Model_Authorizenet_Cards|null
     */
    protected $_cardsStorage;

    /**
     * Fields that should be replaced in debug with '***'
     *
     * @var array
     */
    protected $_debugReplacePrivateDataKeys = [
        'x_login', 'x_tran_key',
        'x_card_num', 'x_exp_date',
        'x_card_code', 'x_bank_aba_code',
        'x_bank_name', 'x_bank_acct_num',
        'x_bank_acct_type','x_bank_acct_name',
        'x_echeck_type',
    ];

    /**
     * Key for storing fraud transaction flag in additional information of payment model
     * @var string
     */
    protected $_isTransactionFraud = 'is_transaction_fraud';

    /**
     * Key for storing transaction id in additional information of payment model
     * @var string
     */
    protected $_realTransactionIdKey = 'real_transaction_id';

    /**
     * Key for storing split tender id in additional information of payment model
     * @var string
     */
    protected $_splitTenderIdKey = 'split_tender_id';

    /**
     * Key for storing locking gateway actions flag in additional information of payment model
     * @var string
     */
    protected $_isGatewayActionsLockedKey = 'is_gateway_actions_locked';

    /**
     * Key for storing partial authorization last action state in session
     * @var string
     */
    protected $_partialAuthorizationLastActionStateSessionKey = 'paygate_authorizenet_last_action_state';

    /**
     * Key for storing partial authorization checksum in session
     * @var string
     */
    protected $_partialAuthorizationChecksumSessionKey = 'paygate_authorizenet_checksum';

    /**
     * Fields for creating place request checksum
     *
     * @var array
     */
    protected $_partialAuthorizationChecksumDataKeys = [
        'x_version', 'x_test_request', 'x_login', 'x_test_request', 'x_allow_partial_auth', 'x_amount',
        'x_currency_code', 'x_type', 'x_first_name', 'x_last_name', 'x_company', 'x_address', 'x_city', 'x_state',
        'x_zip', 'x_country', 'x_phone', 'x_fax', 'x_cust_id', 'x_customer_ip', 'x_customer_tax_id', 'x_email',
        'x_email_customer', 'x_merchant_email', 'x_ship_to_first_name', 'x_ship_to_last_name', 'x_ship_to_company',
        'x_ship_to_address', 'x_ship_to_city', 'x_ship_to_state', 'x_ship_to_zip', 'x_ship_to_country', 'x_po_num',
        'x_tax', 'x_freight',
    ];

    /**
     * Centinel cardinal fields map
     *
     * @var array
     */
    protected $_centinelFieldMap = [
        'centinel_cavv' => 'x_cardholder_authentication_value',
        'centinel_eci'  => 'x_authentication_indicator',
    ];

    /**
     * Check method for processing with base currency
     *
     * @param string $currencyCode
     * @return bool
     */
    #[\Override]
    public function canUseForCurrency($currencyCode)
    {
        if (!in_array($currencyCode, $this->getAcceptedCurrencyCodes())) {
            return false;
        }
        return true;
    }

    /**
     * Return array of currency codes supplied by Payment Gateway
     *
     * @return array
     */
    public function getAcceptedCurrencyCodes()
    {
        if (!$this->hasData('_accepted_currency')) {
            $acceptedCurrencyCodes = $this->_allowCurrencyCode;
            $acceptedCurrencyCodes[] = $this->getConfigData('currency');
            $this->setData('_accepted_currency', $acceptedCurrencyCodes);
        }
        return $this->_getData('_accepted_currency');
    }

    /**
     * Check capture availability
     *
     * @return bool
     */
    #[\Override]
    public function canCapture()
    {
        if ($this->_isGatewayActionsLocked($this->getInfoInstance())) {
            return false;
        }
        if ($this->_isPreauthorizeCapture($this->getInfoInstance())) {
            return true;
        }

        /**
         * If there are not transactions it is placing order and capturing is available
         */
        foreach ($this->getCardsStorage()->getCards() as $card) {
            $lastTransaction = $this->getInfoInstance()->getTransaction($card->getLastTransId());
            if ($lastTransaction) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check refund availability
     *
     * @return bool
     */
    #[\Override]
    public function canRefund()
    {
        if ($this->_isGatewayActionsLocked($this->getInfoInstance())
            || $this->getCardsStorage()->getCardsCount() <= 0
        ) {
            return false;
        }
        foreach ($this->getCardsStorage()->getCards() as $card) {
            $lastTransaction = $this->getInfoInstance()->getTransaction($card->getLastTransId());
            if ($lastTransaction
                && $lastTransaction->getTxnType() == Mage_Sales_Model_Order_Payment_Transaction::TYPE_CAPTURE
                && !$lastTransaction->getIsClosed()
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check void availability
     *
     * @return  bool
     */
    #[\Override]
    public function canVoid(Varien_Object $payment)
    {
        if ($this->_isGatewayActionsLocked($this->getInfoInstance())) {
            return false;
        }
        return $this->_isPreauthorizeCapture($this->getInfoInstance());
    }

    /**
     * Set partial authorization last action state into session
     *
     * @param string $state
     * @return $this
     */
    public function setPartialAuthorizationLastActionState($state)
    {
        $this->_getSession()->setData($this->_partialAuthorizationLastActionStateSessionKey, $state);
        return $this;
    }

    /**
     * Return partial authorization last action state from session
     *
     * @return string
     */
    public function getPartialAuthorizationLastActionState()
    {
        return $this->_getSession()->getData($this->_partialAuthorizationLastActionStateSessionKey);
    }

    /**
     * Unset partial authorization last action state in session
     *
     * @return $this
     */
    public function unsetPartialAuthorizationLastActionState()
    {
        $this->_getSession()->setData($this->_partialAuthorizationLastActionStateSessionKey, false);
        return $this;
    }

    /**
     * Send authorize request to gateway
     *
     * @param  Mage_Sales_Model_Order_Payment $payment
     * @param  float $amount
     * @return $this
     */
    #[\Override]
    public function authorize(Varien_Object $payment, $amount)
    {
        if ($amount <= 0) {
            Mage::throwException(Mage::helper('paygate')->__('Invalid amount for authorization.'));
        }

        $this->_initCardsStorage($payment);

        if ($this->isPartialAuthorization($payment)) {
            $this->_partialAuthorization($payment, $amount, self::REQUEST_TYPE_AUTH_ONLY);
            $payment->setSkipTransactionCreation(true);
            return $this;
        }

        $this->_place($payment, $amount, self::REQUEST_TYPE_AUTH_ONLY);
        $payment->setSkipTransactionCreation(true);
        return $this;
    }

    /**
     * Send capture request to gateway
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param float $amount
     * @return $this
     */
    #[\Override]
    public function capture(Varien_Object $payment, $amount)
    {
        if ($amount <= 0) {
            Mage::throwException(Mage::helper('paygate')->__('Invalid amount for capture.'));
        }
        $this->_initCardsStorage($payment);
        if ($this->_isPreauthorizeCapture($payment)) {
            $this->_preauthorizeCapture($payment, $amount);
        } elseif ($this->isPartialAuthorization($payment)) {
            $this->_partialAuthorization($payment, $amount, self::REQUEST_TYPE_AUTH_CAPTURE);
        } else {
            $this->_place($payment, $amount, self::REQUEST_TYPE_AUTH_CAPTURE);
        }
        $payment->setSkipTransactionCreation(true);
        return $this;
    }

    /**
     * Void the payment through gateway
     *
     * @param  Mage_Sales_Model_Order_Payment $payment
     * @return $this
     */
    #[\Override]
    public function void(Varien_Object $payment)
    {
        $cardsStorage = $this->getCardsStorage($payment);

        $messages = [];
        $isSuccessful = false;
        $isFiled = false;
        foreach ($cardsStorage->getCards() as $card) {
            try {
                $newTransaction = $this->_voidCardTransaction($payment, $card);
                $messages[] = $newTransaction->getMessage();
                $isSuccessful = true;
            } catch (Exception $e) {
                $messages[] = $e->getMessage();
                $isFiled = true;
                continue;
            }
            $cardsStorage->updateCard($card);
        }

        if ($isFiled) {
            $this->_processFailureMultitransactionAction($payment, $messages, $isSuccessful);
        }

        $payment->setSkipTransactionCreation(true);
        return $this;
    }

    /**
     * Cancel the payment through gateway
     *
     * @param  Mage_Sales_Model_Order_Payment $payment
     * @return $this
     */
    #[\Override]
    public function cancel(Varien_Object $payment)
    {
        return $this->void($payment);
    }

    /**
     * Refund the amount with transaction id
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param float $requestedAmount
     * @return $this
     * @throws Mage_Core_Exception
     */
    #[\Override]
    public function refund(Varien_Object $payment, $requestedAmount)
    {
        $cardsStorage = $this->getCardsStorage($payment);

        if ($this->_formatAmount($cardsStorage->getCapturedAmount() - $cardsStorage->getRefundedAmount()) < $requestedAmount) {
            Mage::throwException(Mage::helper('paygate')->__('Invalid amount for refund.'));
        }

        $messages = [];
        $isSuccessful = false;
        $isFiled = false;
        foreach ($cardsStorage->getCards() as $card) {
            if ($requestedAmount > 0) {
                $cardAmountForRefund = $this->_formatAmount($card->getCapturedAmount() - $card->getRefundedAmount());
                if ($cardAmountForRefund <= 0) {
                    continue;
                }
                if ($cardAmountForRefund > $requestedAmount) {
                    $cardAmountForRefund = $requestedAmount;
                }
                try {
                    $newTransaction = $this->_refundCardTransaction($payment, $cardAmountForRefund, $card);
                    $messages[] = $newTransaction->getMessage();
                    $isSuccessful = true;
                } catch (Exception $e) {
                    $messages[] = $e->getMessage();
                    $isFiled = true;
                    continue;
                }
                $card->setRefundedAmount($this->_formatAmount($card->getRefundedAmount() + $cardAmountForRefund));
                $cardsStorage->updateCard($card);
                $requestedAmount = $this->_formatAmount($requestedAmount - $cardAmountForRefund);
            } else {
                $payment->setSkipTransactionCreation(true);
                return $this;
            }
        }

        if ($isFiled) {
            $this->_processFailureMultitransactionAction($payment, $messages, $isSuccessful);
        }

        $payment->setSkipTransactionCreation(true);
        return $this;
    }

    /**
     * Cancel partial authorizations and flush current split_tender_id record
     */
    public function cancelPartialAuthorization(Mage_Payment_Model_Info $payment)
    {
        if (!$payment->getAdditionalInformation($this->_splitTenderIdKey)) {
            Mage::throwException(Mage::helper('paygate')->__('Invalid split tenderId ID.'));
        }

        $request = $this->_getRequest();
        $request->setXSplitTenderId($payment->getAdditionalInformation($this->_splitTenderIdKey));

        $request
            ->setXType(self::REQUEST_TYPE_VOID)
            ->setXMethod(self::REQUEST_METHOD_CC);
        $result = $this->_postRequest($request);

        switch ($result->getResponseCode()) {
            case self::RESPONSE_CODE_APPROVED:
                $payment->setAdditionalInformation($this->_splitTenderIdKey, null);
                $this->_getSession()->setData($this->_partialAuthorizationChecksumSessionKey, null);
                $this->getCardsStorage($payment)->flushCards();
                $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_ALL_CANCELED);
                return;
            default:
                Mage::throwException(Mage::helper('paygate')->__('Payment canceling error.'));
        }
    }

    /**
     * Send request with new payment to gateway
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param float $amount
     * @param self::REQUEST_TYPE_AUTH_* $requestType
     * @return $this
     * @throws Mage_Core_Exception
     */
    protected function _place($payment, $amount, $requestType)
    {
        $payment->setAnetTransType($requestType);
        $payment->setAmount($amount);
        $request = $this->_buildRequest($payment);
        $result = $this->_postRequest($request);

        switch ($requestType) {
            case self::REQUEST_TYPE_AUTH_ONLY:
                $newTransactionType = Mage_Sales_Model_Order_Payment_Transaction::TYPE_AUTH;
                $defaultExceptionMessage = Mage::helper('paygate')->__('Payment authorization error.');
                break;
            case self::REQUEST_TYPE_AUTH_CAPTURE:
                $newTransactionType = Mage_Sales_Model_Order_Payment_Transaction::TYPE_CAPTURE;
                $defaultExceptionMessage = Mage::helper('paygate')->__('Payment capturing error.');
                break;
        }

        switch ($result->getResponseCode()) {
            case self::RESPONSE_CODE_APPROVED:
                $this->getCardsStorage($payment)->flushCards();
                $card = $this->_registerCard($result, $payment);
                $this->_addTransaction(
                    $payment,
                    $card->getLastTransId(),
                    $newTransactionType,
                    ['is_transaction_closed' => 0],
                    [$this->_realTransactionIdKey => $card->getLastTransId()],
                    Mage::helper('paygate')->getTransactionMessage(
                        $payment,
                        $requestType,
                        $card->getLastTransId(),
                        $card,
                        $amount,
                    ),
                );
                if ($requestType == self::REQUEST_TYPE_AUTH_CAPTURE) {
                    $card->setCapturedAmount($card->getProcessedAmount());
                    $this->getCardsStorage($payment)->updateCard($card);
                }
                return $this;
            case self::RESPONSE_CODE_HELD:
                if ($result->getResponseReasonCode() == self::RESPONSE_REASON_CODE_PENDING_REVIEW_AUTHORIZED
                    || $result->getResponseReasonCode() == self::RESPONSE_REASON_CODE_PENDING_REVIEW
                ) {
                    $card = $this->_registerCard($result, $payment);
                    $this->_addTransaction(
                        $payment,
                        $card->getLastTransId(),
                        $newTransactionType,
                        ['is_transaction_closed' => 0],
                        [
                            $this->_realTransactionIdKey => $card->getLastTransId(),
                            $this->_isTransactionFraud => true,
                        ],
                        Mage::helper('paygate')->getTransactionMessage(
                            $payment,
                            $requestType,
                            $card->getLastTransId(),
                            $card,
                            $amount,
                        ),
                    );
                    if ($requestType == self::REQUEST_TYPE_AUTH_CAPTURE) {
                        $card->setCapturedAmount($card->getProcessedAmount());
                        $this->getCardsStorage()->updateCard($card);
                    }
                    $payment
                        ->setIsTransactionPending(true)
                        ->setIsFraudDetected(true);
                    return $this;
                }
                if ($result->getResponseReasonCode() == self::RESPONSE_REASON_CODE_PARTIAL_APPROVE) {
                    $checksum = $this->_generateChecksum($request, $this->_partialAuthorizationChecksumDataKeys);
                    $this->_getSession()->setData($this->_partialAuthorizationChecksumSessionKey, $checksum);
                    if ($this->_processPartialAuthorizationResponse($result, $payment)) {
                        return $this;
                    }
                }
                Mage::throwException($defaultExceptionMessage);
                // no break
            case self::RESPONSE_CODE_DECLINED:
            case self::RESPONSE_CODE_ERROR:
                Mage::throwException($this->_wrapGatewayError($result->getResponseReasonText()));
                // no break
            default:
                Mage::throwException($defaultExceptionMessage);
        }
    }

    /**
     * Send request with new payment to gateway during partial authorization process
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param float $amount
     * @param self::REQUEST_TYPE_AUTH_* $requestType
     * @return $this
     */
    protected function _partialAuthorization($payment, $amount, $requestType)
    {
        $payment->setAnetTransType($requestType);

        /*
         * Try to build checksum of first request and compare with current checksum
         */
        if ($this->getConfigData('partial_authorization_checksum_checking')) {
            $payment->setAmount($amount);
            $firstPlacingRequest = $this->_buildRequest($payment);
            $newChecksum = $this->_generateChecksum($firstPlacingRequest, $this->_partialAuthorizationChecksumDataKeys);
            $previosChecksum = $this->_getSession()->getData($this->_partialAuthorizationChecksumSessionKey);
            if ($newChecksum != $previosChecksum) {
                $quotePayment = $payment->getOrder()->getQuote()->getPayment();
                $this->cancelPartialAuthorization($payment);
                $this->_clearAssignedData($quotePayment);
                $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_DATA_CHANGED);
                $quotePayment->setAdditionalInformation($payment->getAdditionalInformation());
                throw new Mage_Payment_Model_Info_Exception(
                    Mage::helper('paygate')->__('Shopping cart contents and/or address has been changed.'),
                );
            }
        }

        $amount = $amount - $this->getCardsStorage()->getProcessedAmount();
        if ($amount <= 0) {
            Mage::throwException(Mage::helper('paygate')->__('Invalid amount for partial authorization.'));
        }
        $payment->setAmount($amount);
        $request = $this->_buildRequest($payment);
        $result = $this->_postRequest($request);
        $this->_processPartialAuthorizationResponse($result, $payment);

        switch ($requestType) {
            case self::REQUEST_TYPE_AUTH_ONLY:
                $newTransactionType = Mage_Sales_Model_Order_Payment_Transaction::TYPE_AUTH;
                break;
            case self::REQUEST_TYPE_AUTH_CAPTURE:
                $newTransactionType = Mage_Sales_Model_Order_Payment_Transaction::TYPE_CAPTURE;
                break;
        }

        foreach ($this->getCardsStorage()->getCards() as $card) {
            $this->_addTransaction(
                $payment,
                $card->getLastTransId(),
                $newTransactionType,
                ['is_transaction_closed' => 0],
                [$this->_realTransactionIdKey => $card->getLastTransId()],
                Mage::helper('paygate')->getTransactionMessage(
                    $payment,
                    $requestType,
                    $card->getLastTransId(),
                    $card,
                    $card->getProcessedAmount(),
                ),
            );
            if ($requestType == self::REQUEST_TYPE_AUTH_CAPTURE) {
                $card->setCapturedAmount($card->getProcessedAmount());
                $this->getCardsStorage()->updateCard($card);
            }
        }
        $this->_getSession()->setData($this->_partialAuthorizationChecksumSessionKey, null);
        return $this;
    }

    /**
     * Return true if there are authorized transactions
     *
     * @param Mage_Payment_Model_Info $payment
     * @return bool
     */
    protected function _isPreauthorizeCapture($payment)
    {
        if ($this->getCardsStorage()->getCardsCount() <= 0) {
            return false;
        }
        foreach ($this->getCardsStorage()->getCards() as $card) {
            $lastTransaction = $payment->getTransaction($card->getLastTransId());
            if (!$lastTransaction
                || $lastTransaction->getTxnType() != Mage_Sales_Model_Order_Payment_Transaction::TYPE_AUTH
            ) {
                return false;
            }
        }
        return true;
    }

    /**
     * Send capture request to gateway for capture authorized transactions
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param float $requestedAmount
     * @return $this
     */
    protected function _preauthorizeCapture($payment, $requestedAmount)
    {
        $cardsStorage = $this->getCardsStorage($payment);

        if ($this->_formatAmount($cardsStorage->getProcessedAmount() - $cardsStorage->getCapturedAmount()) < $requestedAmount) {
            Mage::throwException(Mage::helper('paygate')->__('Invalid amount for capture.'));
        }

        $messages = [];
        $isSuccessful = false;
        $isFiled = false;
        foreach ($cardsStorage->getCards() as $card) {
            if ($requestedAmount > 0) {
                $cardAmountForCapture = $card->getProcessedAmount();
                if ($cardAmountForCapture > $requestedAmount) {
                    $cardAmountForCapture = $requestedAmount;
                }
                try {
                    $newTransaction = $this->_preauthorizeCaptureCardTransaction(
                        $payment,
                        $cardAmountForCapture,
                        $card,
                    );
                    $messages[] = $newTransaction->getMessage();
                    $isSuccessful = true;
                } catch (Exception $e) {
                    $messages[] = $e->getMessage();
                    $isFiled = true;
                    continue;
                }
                $card->setCapturedAmount($cardAmountForCapture);
                $cardsStorage->updateCard($card);
                $requestedAmount = $this->_formatAmount($requestedAmount - $cardAmountForCapture);
            } else {
                /**
                 * This functional is commented because partial capture is disable. See self::_canCapturePartial.
                 */
                //$this->_voidCardTransaction($payment, $card);
            }
        }

        if ($isFiled) {
            $this->_processFailureMultitransactionAction($payment, $messages, $isSuccessful);
        }
        return $this;
    }

    /**
     * Send capture request to gateway for capture authorized transactions of card
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param float $amount
     * @param Varien_Object $card
     * @return Mage_Sales_Model_Order_Payment_Transaction
     */
    protected function _preauthorizeCaptureCardTransaction($payment, $amount, $card)
    {
        $authTransactionId = $card->getLastTransId();
        $authTransaction = $payment->getTransaction($authTransactionId);
        $realAuthTransactionId = $authTransaction->getAdditionalInformation($this->_realTransactionIdKey);

        $payment->setAnetTransType(self::REQUEST_TYPE_PRIOR_AUTH_CAPTURE);
        $payment->setXTransId($realAuthTransactionId);
        $payment->setAmount($amount);

        $request = $this->_buildRequest($payment);
        $result = $this->_postRequest($request);

        switch ($result->getResponseCode()) {
            case self::RESPONSE_CODE_APPROVED:
                if ($result->getResponseReasonCode() == self::RESPONSE_REASON_CODE_APPROVED) {
                    $captureTransactionId = $result->getTransactionId() . '-capture';
                    $card->setLastTransId($captureTransactionId);
                    return $this->_addTransaction(
                        $payment,
                        $captureTransactionId,
                        Mage_Sales_Model_Order_Payment_Transaction::TYPE_CAPTURE,
                        [
                            'is_transaction_closed' => 0,
                            'parent_transaction_id' => $authTransactionId,
                        ],
                        [$this->_realTransactionIdKey => $result->getTransactionId()],
                        Mage::helper('paygate')->getTransactionMessage(
                            $payment,
                            self::REQUEST_TYPE_PRIOR_AUTH_CAPTURE,
                            $result->getTransactionId(),
                            $card,
                            $amount,
                        ),
                    );
                }
                $exceptionMessage = $this->_wrapGatewayError($result->getResponseReasonText());
                break;
            case self::RESPONSE_CODE_HELD:
            case self::RESPONSE_CODE_DECLINED:
            case self::RESPONSE_CODE_ERROR:
                $exceptionMessage = $this->_wrapGatewayError($result->getResponseReasonText());
                break;
            default:
                $exceptionMessage = Mage::helper('paygate')->__('Payment capturing error.');
                break;
        }

        $exceptionMessage = Mage::helper('paygate')->getTransactionMessage(
            $payment,
            self::REQUEST_TYPE_PRIOR_AUTH_CAPTURE,
            $realAuthTransactionId,
            $card,
            $amount,
            $exceptionMessage,
        );
        Mage::throwException($exceptionMessage);
    }

    /**
     * Void the card transaction through gateway
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param Varien_Object $card
     * @return Mage_Sales_Model_Order_Payment_Transaction
     */
    protected function _voidCardTransaction($payment, $card)
    {
        $authTransactionId = $card->getLastTransId();
        $authTransaction = $payment->getTransaction($authTransactionId);
        $realAuthTransactionId = $authTransaction->getAdditionalInformation($this->_realTransactionIdKey);

        $payment->setAnetTransType(self::REQUEST_TYPE_VOID);
        $payment->setXTransId($realAuthTransactionId);

        $request = $this->_buildRequest($payment);
        $result = $this->_postRequest($request);

        switch ($result->getResponseCode()) {
            case self::RESPONSE_CODE_APPROVED:
                if ($result->getResponseReasonCode() == self::RESPONSE_REASON_CODE_APPROVED) {
                    $voidTransactionId = $result->getTransactionId() . '-void';
                    $card->setLastTransId($voidTransactionId);
                    return $this->_addTransaction(
                        $payment,
                        $voidTransactionId,
                        Mage_Sales_Model_Order_Payment_Transaction::TYPE_VOID,
                        [
                            'is_transaction_closed' => 1,
                            'should_close_parent_transaction' => 1,
                            'parent_transaction_id' => $authTransactionId,
                        ],
                        [$this->_realTransactionIdKey => $result->getTransactionId()],
                        Mage::helper('paygate')->getTransactionMessage(
                            $payment,
                            self::REQUEST_TYPE_VOID,
                            $result->getTransactionId(),
                            $card,
                        ),
                    );
                }
                $exceptionMessage = $this->_wrapGatewayError($result->getResponseReasonText());
                break;
            case self::RESPONSE_CODE_DECLINED:
            case self::RESPONSE_CODE_ERROR:
                if ($result->getResponseReasonCode() == self::RESPONSE_REASON_CODE_NOT_FOUND
                    && $this->_isTransactionExpired($realAuthTransactionId)
                ) {
                    $voidTransactionId = $realAuthTransactionId . '-void';
                    return $this->_addTransaction(
                        $payment,
                        $voidTransactionId,
                        Mage_Sales_Model_Order_Payment_Transaction::TYPE_VOID,
                        [
                            'is_transaction_closed' => 1,
                            'should_close_parent_transaction' => 1,
                            'parent_transaction_id' => $authTransactionId,
                        ],
                        [],
                        Mage::helper('paygate')->getExtendedTransactionMessage(
                            $payment,
                            self::REQUEST_TYPE_VOID,
                            null,
                            $card,
                            false,
                            false,
                            Mage::helper('paygate')->__('Parent Authorize.Net transaction (ID %s) expired', $realAuthTransactionId),
                        ),
                    );
                }
                $exceptionMessage = $this->_wrapGatewayError($result->getResponseReasonText());
                break;
            default:
                $exceptionMessage = Mage::helper('paygate')->__('Payment voiding error.');
                break;
        }

        $exceptionMessage = Mage::helper('paygate')->getTransactionMessage(
            $payment,
            self::REQUEST_TYPE_VOID,
            $realAuthTransactionId,
            $card,
            false,
            $exceptionMessage,
        );
        Mage::throwException($exceptionMessage);
    }

    /**
     * Check if transaction is expired
     *
     * @param  string $realAuthTransactionId
     * @return bool
     */
    protected function _isTransactionExpired($realAuthTransactionId)
    {
        $transactionDetails = $this->_getTransactionDetails($realAuthTransactionId);
        return $transactionDetails->getTransactionStatus() == self::TRANSACTION_STATUS_EXPIRED;
    }

    /**
     * Refund the card transaction through gateway
     *
     * @param Mage_Sales_Model_Order_Payment $payment
     * @param Varien_Object $card
     * @return Mage_Sales_Model_Order_Payment_Transaction
     */
    protected function _refundCardTransaction($payment, $amount, $card)
    {
        /**
         * Card has last transaction with type "refund" when all captured amount is refunded.
         * Until this moment card has last transaction with type "capture".
         */
        $captureTransactionId = $card->getLastTransId();
        $captureTransaction = $payment->getTransaction($captureTransactionId);
        $realCaptureTransactionId = $captureTransaction->getAdditionalInformation($this->_realTransactionIdKey);

        $payment->setAnetTransType(self::REQUEST_TYPE_CREDIT);
        $payment->setXTransId($realCaptureTransactionId);
        $payment->setAmount($amount);

        $request = $this->_buildRequest($payment);
        $request->setXCardNum($card->getCcLast4());
        $result = $this->_postRequest($request);

        switch ($result->getResponseCode()) {
            case self::RESPONSE_CODE_APPROVED:
                if ($result->getResponseReasonCode() == self::RESPONSE_REASON_CODE_APPROVED) {
                    $refundTransactionId = $result->getTransactionId() . '-refund';
                    $shouldCloseCaptureTransaction = 0;
                    /**
                     * If it is last amount for refund, transaction with type "capture" will be closed
                     * and card will has last transaction with type "refund"
                     */
                    if ($this->_formatAmount($card->getCapturedAmount() - $card->getRefundedAmount()) == $amount) {
                        $card->setLastTransId($refundTransactionId);
                        $shouldCloseCaptureTransaction = 1;
                    }
                    return $this->_addTransaction(
                        $payment,
                        $refundTransactionId,
                        Mage_Sales_Model_Order_Payment_Transaction::TYPE_REFUND,
                        [
                            'is_transaction_closed' => 1,
                            'should_close_parent_transaction' => $shouldCloseCaptureTransaction,
                            'parent_transaction_id' => $captureTransactionId,
                        ],
                        [$this->_realTransactionIdKey => $result->getTransactionId()],
                        Mage::helper('paygate')->getTransactionMessage(
                            $payment,
                            self::REQUEST_TYPE_CREDIT,
                            $result->getTransactionId(),
                            $card,
                            $amount,
                        ),
                    );
                }
                $exceptionMessage = $this->_wrapGatewayError($result->getResponseReasonText());
                break;
            case self::RESPONSE_CODE_DECLINED:
            case self::RESPONSE_CODE_ERROR:
                $exceptionMessage = $this->_wrapGatewayError($result->getResponseReasonText());
                break;
            default:
                $exceptionMessage = Mage::helper('paygate')->__('Payment refunding error.');
                break;
        }

        $exceptionMessage = Mage::helper('paygate')->getTransactionMessage(
            $payment,
            self::REQUEST_TYPE_CREDIT,
            $realCaptureTransactionId,
            $card,
            $amount,
            $exceptionMessage,
        );
        Mage::throwException($exceptionMessage);
    }

    /**
     * Init cards storage model
     *
     * @param Mage_Payment_Model_Info $payment
     */
    protected function _initCardsStorage($payment)
    {
        $this->_cardsStorage = Mage::getModel('paygate/authorizenet_cards')->setPayment($payment);
    }

    /**
     * Return cards storage model
     *
     * @param Mage_Payment_Model_Info $payment
     * @return Mage_Paygate_Model_Authorizenet_Cards
     */
    public function getCardsStorage($payment = null)
    {
        if (is_null($payment)) {
            $payment = $this->getInfoInstance();
        }
        if (is_null($this->_cardsStorage)) {
            $this->_initCardsStorage($payment);
        }
        return $this->_cardsStorage;
    }

    /**
     * If partial authorization is started method will return true
     *
     * @param Mage_Payment_Model_Info $payment
     * @return bool
     */
    public function isPartialAuthorization($payment = null)
    {
        if (is_null($payment)) {
            $payment = $this->getInfoInstance();
        }
        return $payment->getAdditionalInformation($this->_splitTenderIdKey);
    }

    /**
     * Mock capture transaction id in invoice
     *
     * @param Mage_Sales_Model_Order_Invoice $invoice
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return Mage_Payment_Model_Method_Abstract
     */
    #[\Override]
    public function processInvoice($invoice, $payment)
    {
        $invoice->setTransactionId(1);
        return $this;
    }

    /**
     * Set transaction ID into creditmemo for informational purposes
     * @param Mage_Sales_Model_Order_Creditmemo $creditmemo
     * @param Mage_Sales_Model_Order_Payment $payment
     * @return Mage_Payment_Model_Method_Abstract
     */
    #[\Override]
    public function processCreditmemo($creditmemo, $payment)
    {
        $creditmemo->setTransactionId(1);
        return $this;
    }

    /**
     * Fetch transaction details info
     *
     * Update transaction info if there is one placing transaction only
     *
     * @param string $transactionId
     * @return array
     */
    #[\Override]
    public function fetchTransactionInfo(Mage_Payment_Model_Info $payment, $transactionId)
    {
        $data = parent::fetchTransactionInfo($payment, $transactionId);
        $cardsStorage = $this->getCardsStorage($payment);

        if ($cardsStorage->getCardsCount() != 1) {
            return $data;
        }
        $cards = $cardsStorage->getCards();
        $card = array_shift($cards);

        /*
         * We need try to get transaction from Mage::registry,
         * because in cases when fetch calling from Mage_Adminhtml_Sales_TransactionsController::fetchAction()
         * this line "$transaction = $payment->getTransaction($transactionId)" loads a fetching transaction into a new object,
         * so some changes (for ex. $transaction->setAdditionalInformation($this->_isTransactionFraud, false) ) will not saved,
         * because controller have another object for this transaction and Mage_Sales_Model_Order_Payment_Transaction::RAW_DETAILS isn't includes _isTransactionFraud flag.
         */
        $transaction = Mage::registry('current_transaction');
        if (is_null($transaction)) {
            //this is for payment info update:
            $transactionId = $card->getLastTransId();
            $transaction = $payment->getTransaction($transactionId);
        }
        //because in child transaction, the txn_id spoils by added additional word (@see $this->_preauthorizeCaptureCardTransaction()):
        if (empty($transactionId) || $transaction->getParentId()) {
            $transactionId = $transaction->getAdditionalInformation($this->_realTransactionIdKey);
        }
        $response = $this->_getTransactionDetails($transactionId);
        $data = array_merge($data, $response->getData());

        if ($response->getResponseCode() == self::RESPONSE_CODE_APPROVED) {
            $transaction->setAdditionalInformation($this->_isTransactionFraud, false);
            $payment->setIsTransactionApproved(true);
        } elseif ($response->getResponseReasonCode() == self::RESPONSE_REASON_CODE_PENDING_REVIEW_DECLINED) {
            $payment->setIsTransactionDenied(true);
        }
        return $data;
    }

    /**
     * Set split_tender_id to quote payment if needed
     *
     * @param Mage_Paygate_Model_Authorizenet_Result $response
     * @param Mage_Sales_Model_Order_Payment $orderPayment
     * @return bool
     */
    protected function _processPartialAuthorizationResponse($response, $orderPayment)
    {
        if (!$response->getSplitTenderId()) {
            return false;
        }

        $quotePayment = $orderPayment->getOrder()->getQuote()->getPayment();
        $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_LAST_DECLINED);
        $exceptionMessage = null;

        try {
            switch ($response->getResponseCode()) {
                case self::RESPONSE_CODE_APPROVED:
                    $this->_registerCard($response, $orderPayment);
                    $this->_clearAssignedData($quotePayment);
                    $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_LAST_SUCCESS);
                    return true;
                case self::RESPONSE_CODE_HELD:
                    if ($response->getResponseReasonCode() != self::RESPONSE_REASON_CODE_PARTIAL_APPROVE) {
                        return false;
                    }
                    if ($this->getCardsStorage($orderPayment)->getCardsCount() + 1 >= self::PARTIAL_AUTH_CARDS_LIMIT) {
                        $this->cancelPartialAuthorization($orderPayment);
                        $this->_clearAssignedData($quotePayment);
                        $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_CARDS_LIMIT_EXCEEDED);
                        $quotePayment->setAdditionalInformation($orderPayment->getAdditionalInformation());
                        $exceptionMessage = Mage::helper('paygate')->__('You have reached the maximum number of credit card allowed to be used for the payment.');
                        break;
                    }
                    $orderPayment->setAdditionalInformation($this->_splitTenderIdKey, $response->getSplitTenderId());
                    $this->_registerCard($response, $orderPayment);
                    $this->_clearAssignedData($quotePayment);
                    $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_LAST_SUCCESS);
                    $quotePayment->setAdditionalInformation($orderPayment->getAdditionalInformation());
                    $exceptionMessage = null;
                    break;
                case self::RESPONSE_CODE_DECLINED:
                case self::RESPONSE_CODE_ERROR:
                    $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_LAST_DECLINED);
                    $quotePayment->setAdditionalInformation($orderPayment->getAdditionalInformation());
                    $exceptionMessage = $this->_wrapGatewayError($response->getResponseReasonText());
                    break;
                default:
                    $this->setPartialAuthorizationLastActionState(self::PARTIAL_AUTH_LAST_DECLINED);
                    $quotePayment->setAdditionalInformation($orderPayment->getAdditionalInformation());
                    $exceptionMessage = $this->_wrapGatewayError(
                        Mage::helper('paygate')->__('Payment partial authorization error.'),
                    );
            }
        } catch (Exception $e) {
            $exceptionMessage = $e->getMessage();
        }

        throw new Mage_Payment_Model_Info_Exception($exceptionMessage);
    }

    /**
     * Return authorize payment request
     *
     * @return Mage_Paygate_Model_Authorizenet_Request
     */
    protected function _getRequest()
    {
        return Mage::getModel('paygate/authorizenet_request')
            ->setXVersion(3.1)
            ->setXDelimData('True')
            ->setXRelayResponse('False')
            ->setXTestRequest($this->getConfigData('test') ? 'TRUE' : 'FALSE')
            ->setXLogin($this->getConfigData('login'))
            ->setXTranKey($this->getConfigData('trans_key'));
    }

    /**
     * Prepare request to gateway
     *
     * @link http://www.authorize.net/support/AIM_guide.pdf
     * @param Mage_Payment_Model_Info $payment
     * @return Mage_Paygate_Model_Authorizenet_Request
     */
    protected function _buildRequest(Varien_Object $payment)
    {
        $order = $payment->getOrder();

        $this->setStore($order->getStoreId());

        $request = $this->_getRequest()
            ->setXType($payment->getAnetTransType())
            ->setXMethod(self::REQUEST_METHOD_CC);

        if ($order && $order->getIncrementId()) {
            $request->setXInvoiceNum($order->getIncrementId());
        }

        if ($payment->getAmount()) {
            $request->setXAmount($payment->getAmount(), 2);
            $request->setXCurrencyCode($order->getBaseCurrencyCode());
        }

        switch ($payment->getAnetTransType()) {
            case self::REQUEST_TYPE_AUTH_CAPTURE:
                $request->setXAllowPartialAuth($this->getConfigData('allow_partial_authorization') ? 'True' : 'False');
                if ($payment->getAdditionalInformation($this->_splitTenderIdKey)) {
                    $request->setXSplitTenderId($payment->getAdditionalInformation($this->_splitTenderIdKey));
                }
                break;
            case self::REQUEST_TYPE_AUTH_ONLY:
                $request->setXAllowPartialAuth($this->getConfigData('allow_partial_authorization') ? 'True' : 'False');
                if ($payment->getAdditionalInformation($this->_splitTenderIdKey)) {
                    $request->setXSplitTenderId($payment->getAdditionalInformation($this->_splitTenderIdKey));
                }
                break;
            case self::REQUEST_TYPE_CREDIT:
                /**
                 * Send last 4 digits of credit card number to authorize.net
                 * otherwise it will give an error
                 */
                $request->setXCardNum($payment->getCcLast4());
                $request->setXTransId($payment->getXTransId());
                break;
            case self::REQUEST_TYPE_VOID:
                $request->setXTransId($payment->getXTransId());
                break;
            case self::REQUEST_TYPE_PRIOR_AUTH_CAPTURE:
                $request->setXTransId($payment->getXTransId());
                break;
            case self::REQUEST_TYPE_CAPTURE_ONLY:
                $request->setXAuthCode($payment->getCcAuthCode());
                break;
        }

        if (!empty($order)) {
            $billing = $order->getBillingAddress();
            if (!empty($billing)) {
                $request->setXFirstName($billing->getFirstname())
                    ->setXLastName($billing->getLastname())
                    ->setXCompany($billing->getCompany())
                    ->setXAddress($billing->getStreet(1))
                    ->setXCity($billing->getCity())
                    ->setXState($billing->getRegion())
                    ->setXZip($billing->getPostcode())
                    ->setXCountry($billing->getCountry())
                    ->setXPhone($billing->getTelephone())
                    ->setXFax($billing->getFax())
                    ->setXCustId($order->getCustomerId())
                    ->setXCustomerIp($order->getRemoteIp())
                    ->setXCustomerTaxId($billing->getTaxId())
                    ->setXEmail($order->getCustomerEmail())
                    ->setXEmailCustomer($this->getConfigData('email_customer'))
                    ->setXMerchantEmail($this->getConfigData('merchant_email'));
            }

            $shipping = $order->getShippingAddress();
            if (!empty($shipping)) {
                $request->setXShipToFirstName($shipping->getFirstname())
                    ->setXShipToLastName($shipping->getLastname())
                    ->setXShipToCompany($shipping->getCompany())
                    ->setXShipToAddress($shipping->getStreet(1))
                    ->setXShipToCity($shipping->getCity())
                    ->setXShipToState($shipping->getRegion())
                    ->setXShipToZip($shipping->getPostcode())
                    ->setXShipToCountry($shipping->getCountry());
            }

            $request->setXPoNum($payment->getPoNumber())
                ->setXTax($order->getBaseTaxAmount())
                ->setXFreight($order->getBaseShippingAmount());
        }

        if ($payment->getCcNumber()) {
            $request->setXCardNum($payment->getCcNumber())
                ->setXExpDate(sprintf('%02d-%04d', $payment->getCcExpMonth(), $payment->getCcExpYear()))
                ->setXCardCode($payment->getCcCid());
        }

        return $request;
    }

    /**
     * Post request to gateway and return response
     *
     * @param Mage_Paygate_Model_Authorizenet_Request $request)
     * @return Mage_Paygate_Model_Authorizenet_Result
     */
    protected function _postRequest(Varien_Object $request)
    {
        $debugData = ['request' => $request->getData()];

        $result = Mage::getModel('paygate/authorizenet_result');

        $client = \Symfony\Component\HttpClient\HttpClient::create([
            'max_redirects' => 0,
            'timeout' => 30,
            'verify_host' => true,
            'verify_peer' => true,
        ]);

        $uri = $this->getConfigData('cgi_url');
        $uri = $uri ?: self::CGI_URL;

        foreach ($request->getData() as $key => $value) {
            $request->setData($key, str_replace(self::RESPONSE_DELIM_CHAR, '', $value ?? ''));
        }
        $request->setXDelimChar(self::RESPONSE_DELIM_CHAR);

        try {
            $response = $client->request('POST', $uri, [
                'body' => $request->getData(),
            ]);
        } catch (Exception $e) {
            $result->setResponseCode(-1)
                ->setResponseReasonCode($e->getCode())
                ->setResponseReasonText($e->getMessage());

            $debugData['result'] = $result->getData();
            $this->_debug($debugData);
            Mage::throwException($this->_wrapGatewayError($e->getMessage()));
        }

        $responseBody = $response->getContent();

        $r = explode(self::RESPONSE_DELIM_CHAR, $responseBody);

        if ($r) {
            $result->setResponseCode((int) str_replace('"', '', $r[0]))
                ->setResponseSubcode((int) str_replace('"', '', $r[1]))
                ->setResponseReasonCode((int) str_replace('"', '', $r[2]))
                ->setResponseReasonText($r[3])
                ->setApprovalCode($r[4])
                ->setAvsResultCode($r[5])
                ->setTransactionId($r[6])
                ->setInvoiceNumber($r[7])
                ->setDescription($r[8])
                ->setAmount($r[9])
                ->setMethod($r[10])
                ->setTransactionType($r[11])
                ->setCustomerId($r[12])
                ->setMd5Hash($r[37])
                ->setCardCodeResponseCode($r[38])
                ->setCAVVResponseCode($r[39] ?? null)
                ->setSplitTenderId($r[52])
                ->setAccNumber($r[50])
                ->setCardType($r[51])
                ->setRequestedAmount($r[53])
                ->setBalanceOnCard($r[54])
            ;
        } else {
            Mage::throwException(
                Mage::helper('paygate')->__('Error in payment gateway.'),
            );
        }

        $debugData['result'] = $result->getData();
        $this->_debug($debugData);

        return $result;
    }

    /**
     * Gateway response wrapper
     *
     * @param string $text
     * @return string
     */
    protected function _wrapGatewayError($text)
    {
        return Mage::helper('paygate')->__('Gateway error: %s', $text);
    }

    /**
     * Retrieve session object
     *
     * @return Mage_Core_Model_Session_Abstract
     */
    protected function _getSession()
    {
        if (Mage::app()->getStore()->isAdmin()) {
            return Mage::getSingleton('adminhtml/session_quote');
        } else {
            return Mage::getSingleton('checkout/session');
        }
    }

    /**
     * It sets card`s data into additional information of payment model
     *
     * @param Mage_Paygate_Model_Authorizenet_Result $response
     * @return Varien_Object
     */
    protected function _registerCard(Varien_Object $response, Mage_Sales_Model_Order_Payment $payment)
    {
        $cardsStorage = $this->getCardsStorage($payment);
        $card = $cardsStorage->registerCard();
        $card
            ->setRequestedAmount($response->getRequestedAmount())
            ->setBalanceOnCard($response->getBalanceOnCard())
            ->setLastTransId($response->getTransactionId())
            ->setProcessedAmount($response->getAmount())
            ->setCcType($payment->getCcType())
            ->setCcOwner($payment->getCcOwner())
            ->setCcLast4($payment->getCcLast4())
            ->setCcExpMonth($payment->getCcExpMonth())
            ->setCcExpYear($payment->getCcExpYear())
            ->setCcSsIssue($payment->getCcSsIssue())
            ->setCcSsStartMonth($payment->getCcSsStartMonth())
            ->setCcSsStartYear($payment->getCcSsStartYear());

        $cardsStorage->updateCard($card);
        $this->_clearAssignedData($payment);
        return $card;
    }

    /**
     * Reset assigned data in payment info model
     *
     * @param Mage_Payment_Model_Info $payment
     * @return $this
     */
    private function _clearAssignedData($payment)
    {
        $payment->setCcType(null)
            ->setCcOwner(null)
            ->setCcLast4(null)
            ->setCcNumber(null)
            ->setCcCid(null)
            ->setCcExpMonth(null)
            ->setCcExpYear(null)
            ->setCcSsIssue(null)
            ->setCcSsStartMonth(null)
            ->setCcSsStartYear(null)
        ;
        return $this;
    }

    /**
     * Add payment transaction
     *
     * @param string $transactionId
     * @param string $transactionType
     * @return null|Mage_Sales_Model_Order_Payment_Transaction
     */
    protected function _addTransaction(
        Mage_Sales_Model_Order_Payment $payment,
        $transactionId,
        $transactionType,
        array $transactionDetails = [],
        array $transactionAdditionalInfo = [],
        $message = false,
    ) {
        $payment->setTransactionId($transactionId);
        $payment->resetTransactionAdditionalInfo();
        foreach ($transactionDetails as $key => $value) {
            $payment->setData($key, $value);
        }
        foreach ($transactionAdditionalInfo as $key => $value) {
            $payment->setTransactionAdditionalInfo($key, $value);
        }
        $transaction = $payment->addTransaction($transactionType, null, false, $message);
        foreach (array_keys($transactionDetails) as $key) {
            $payment->unsetData($key);
        }
        $payment->unsLastTransId();

        /**
         * It for self using
         */
        $transaction->setMessage($message);

        return $transaction;
    }

    /**
     * Round up and cast specified amount to float or string
     *
     * @param string|float $amount
     * @param bool $asFloat
     * @return string|float
     */
    protected function _formatAmount($amount, $asFloat = false)
    {
        $amount = sprintf('%.2F', $amount); // "f" depends on locale, "F" doesn't
        return $asFloat ? (float) $amount : $amount;
    }

    /**
     * If gateway actions are locked return true
     *
     * @param  Mage_Payment_Model_Info $payment
     * @return bool
     */
    protected function _isGatewayActionsLocked($payment)
    {
        return $payment->getAdditionalInformation($this->_isGatewayActionsLockedKey);
    }

    /**
     * Process exceptions for gateway action with a lot of transactions
     *
     * @param  Mage_Payment_Model_Info $payment
     * @param  array $messages
     * @param  bool $isSuccessfulTransactions
     */
    protected function _processFailureMultitransactionAction($payment, $messages, $isSuccessfulTransactions)
    {
        if ($isSuccessfulTransactions) {
            $messages[] = Mage::helper('paygate')->__('Gateway actions are locked because the gateway cannot complete one or more of the transactions. Please log in to your Authorize.Net account to manually resolve the issue(s).');
            /**
             * If there is successful transactions we can not to cancel order but
             * have to save information about processed transactions in order`s comments and disable
             * opportunity to voiding\capturing\refunding in future. Current order and payment will not be saved because we have to
             * load new order object and set information into this object.
             */
            $currentOrderId = $payment->getOrder()->getId();
            $copyOrder = Mage::getModel('sales/order')->load($currentOrderId);
            $copyOrder->getPayment()->setAdditionalInformation($this->_isGatewayActionsLockedKey, 1);
            foreach ($messages as $message) {
                $copyOrder->addStatusHistoryComment($message);
            }
            $copyOrder->save();
        }
        Mage::throwException(Mage::helper('paygate')->convertMessagesToMessage($messages));
    }

    /**
     * Generate checksum for object
     *
     * @param array $checkSumDataKeys
     * @return string
     */
    protected function _generateChecksum(Varien_Object $object, $checkSumDataKeys = [])
    {
        $data = [];
        foreach ($checkSumDataKeys as $dataKey) {
            $data[] = $dataKey;
            $data[] = $object->getData($dataKey);
        }
        return md5(implode('_', $data));
    }

    /**
     * This function returns full transaction details for a specified transaction ID.
     *
     * @link http://www.authorize.net/support/ReportingGuide_XML.pdf
     * @link http://developer.authorize.net/api/transaction_details/
     * @param string $transactionId
     * @return Varien_Object
     */
    protected function _getTransactionDetails($transactionId)
    {
        $requestBody = sprintf(
            '<?xml version="1.0" encoding="utf-8"?>'
            . '<getTransactionDetailsRequest xmlns="AnetApi/xml/v1/schema/AnetApiSchema.xsd">'
            . '<merchantAuthentication><name>%s</name><transactionKey>%s</transactionKey></merchantAuthentication>'
            . '<transId>%s</transId>'
            . '</getTransactionDetailsRequest>',
            $this->getConfigData('login'),
            $this->getConfigData('trans_key'),
            $transactionId,
        );

        $client = \Symfony\Component\HttpClient\HttpClient::create([
            'timeout' => 45,
            'verify_host' => true,
            'verify_peer' => true,
        ]);
        $uri = $this->getConfigData('cgi_url_td');
        $uri = $uri ?: self::CGI_URL_TD;

        $debugData = [
            'url' => $uri,
            'request' => $requestBody,
        ];

        try {
            $response = $client->request('POST', $uri, [
                'headers' => ['Content-Type' => 'text/xml'],
                'body' => $requestBody,
            ]);
            $responseBody = $response->getContent();
            $debugData['result'] = $responseBody;
            libxml_use_internal_errors(true);
            $responseXmlDocument = new Varien_Simplexml_Element($responseBody);
            libxml_use_internal_errors(false);
        } catch (Exception $e) {
            $debugData['exception'] = $e->getMessage();
            $this->_debug($debugData);
            Mage::throwException(Mage::helper('paygate')->__('Payment updating error.'));
        }

        $this->_debug($debugData);

        return $this->_parseTransactionDetailsXmlResponseToVarienObject($responseXmlDocument);
    }

    /**
     * Parses xml response object with full transaction details to Varien_Object
     *
     * @param Varien_Simplexml_Element $responseXmlDocument - xml object with full transaction details for a specified transaction ID
     * @return Varien_Object
     */
    protected function _parseTransactionDetailsXmlResponseToVarienObject(Varien_Simplexml_Element $responseXmlDocument)
    {
        $response = new Varien_Object();
        $responseTransactionXmlDocument = $responseXmlDocument->transaction;
        //main fields for generating order status:
        $response
            ->setResponseCode((string) $responseTransactionXmlDocument->responseCode)
            ->setResponseReasonCode((string) $responseTransactionXmlDocument->responseReasonCode)
            ->setTransactionStatus((string) $responseTransactionXmlDocument->transactionStatus)
        ;
        //some additional fields:
        isset($responseTransactionXmlDocument->responseReasonDescription) && $response->setResponseReasonDescription((string) $responseTransactionXmlDocument->responseReasonDescription);
        isset($responseTransactionXmlDocument->FDSFilterAction)           && $response->setFdsFilterAction((string) $responseTransactionXmlDocument->FDSFilterAction);
        isset($responseTransactionXmlDocument->FDSFilters)                && $response->setFdsFilters(serialize($responseTransactionXmlDocument->FDSFilters->asArray()));
        isset($responseTransactionXmlDocument->transactionType)           && $response->setTransactionType((string) $responseTransactionXmlDocument->transactionType);
        isset($responseTransactionXmlDocument->submitTimeUTC)             && $response->setSubmitTimeUtc((string) $responseTransactionXmlDocument->submitTimeUTC);
        isset($responseTransactionXmlDocument->submitTimeLocal)           && $response->setSubmitTimeLocal((string) $responseTransactionXmlDocument->submitTimeLocal);

        return $response;
    }
}
