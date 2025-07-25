<?php

/**
 * Maho
 *
 * @package    Mage_Paypal
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Paypal_Model_Ipn
{
    /**
     * Default log filename
     *
     * @var string
     */
    public const DEFAULT_LOG_FILE = 'paypal_unknown_ipn.log';

    /**
     * Store order instance
     *
     * @var Mage_Sales_Model_Order|null
     */
    protected $_order = null;

    /**
     * Recurring profile instance
     *
     * @var Mage_Sales_Model_Recurring_Profile|null
     */
    protected $_recurringProfile = null;

    /**
     *
     * @var Mage_Paypal_Model_Config
     */
    protected $_config = null;

    /**
     * PayPal info instance
     *
     * @var Mage_Paypal_Model_Info
     */
    protected $_info = null;

    /**
     * IPN request data
     * @var array
     */
    protected $_request = [];

    /**
     * Collected debug information
     *
     * @var array
     */
    protected $_debugData = [];

    /**
     * IPN request data getter
     *
     * @param string $key
     * @return array|string
     */
    public function getRequestData($key = null)
    {
        if ($key === null) {
            return $this->_request;
        }
        return $this->_request[$key] ?? null;
    }

    /**
     * Get ipn data, send verification to PayPal, run corresponding handler
     *
     * @throws Mage_Core_Exception
     */
    public function processIpnRequest(array $request, bool $validateRequest = true)
    {
        $this->_request   = $request;
        $this->_debugData = ['ipn' => $request];
        ksort($this->_debugData['ipn']);

        try {
            if (isset($this->_request['txn_type']) && $this->_request['txn_type'] == 'recurring_payment') {
                $this->_getRecurringProfile();
                if ($validateRequest) {
                    $this->_postBack();
                }
                $this->_processRecurringProfile();
            } else {
                $this->_getOrder();
                if ($validateRequest) {
                    $this->_postBack();
                }
                $this->_processOrder();
            }
        } catch (Exception $e) {
            $this->_debugData['exception'] = $e->getMessage();
            $this->_debug();
            throw $e;
        }
        $this->_debug();
    }

    /**
     * Post back to PayPal to check whether this request is a valid one
     *
     * @throws Exception
     */
    protected function _postBack()
    {
        $postbackQuery = http_build_query($this->_request) . '&cmd=_notify-validate';
        $postbackUrl = $this->_config->getPostbackUrl();
        $this->_debugData['postback_to'] = $postbackUrl;

        $client = \Symfony\Component\HttpClient\HttpClient::create([
            'verify_peer' => $this->_config->verifyPeer,
        ]);

        try {
            $response = $client->request('POST', $postbackUrl, [
                'headers' => ['Connection' => 'close'],
                'body' => $postbackQuery,
            ]);

            $statusCode = $response->getStatusCode();
            $responseBody = $response->getContent();
        } catch (Exception $e) {
            $this->_debugData['http_error'] = ['error' => $e->getMessage(), 'code' => $e->getCode()];
            throw $e;
        }

        /*
         * Handle errors on PayPal side.
         */
        if (empty($responseBody) || in_array($statusCode, [500, 502, 503])) {
            if (empty($responseBody)) {
                $reason = 'Empty response.';
            } else {
                $reason = 'Response code: ' . $statusCode . '.';
            }
            $this->_debugData['exception'] = 'PayPal IPN postback failure. ' . $reason;
            throw new Mage_Paypal_UnavailableException($reason);
        }

        $responseContent = trim($responseBody);
        if ($responseContent != 'VERIFIED') {
            $this->_debugData['postback'] = $postbackQuery;
            $this->_debugData['postback_result'] = $responseBody;
            throw new Exception('PayPal IPN postback failure. See ' . self::DEFAULT_LOG_FILE . ' for details.');
        }
    }

    /**
     * Load and validate order, instantiate proper configuration
     *
     *
     * @return Mage_Sales_Model_Order
     * @throws Exception
     */
    protected function _getOrder()
    {
        if (empty($this->_order)) {
            // get proper order
            $id = $this->_request['invoice'];
            $this->_order = Mage::getModel('sales/order')->loadByIncrementId($id);
            if (!$this->_order->getId()) {
                $this->_debugData['exception'] = sprintf('Wrong order ID: "%s".', $id);
                $this->_debug();
                Mage::app()->getResponse()
                    ->setHeader('HTTP/1.1', '503 Service Unavailable')
                    ->sendResponse();
                exit;
            }
            // re-initialize config with the method code and store id
            $methodCode = $this->_order->getPayment()->getMethod();
            $this->_config = Mage::getModel('paypal/config', [$methodCode, $this->_order->getStoreId()]);
            if (!$this->_config->isMethodActive($methodCode) || !$this->_config->isMethodAvailable()) {
                throw new Exception(sprintf('Method "%s" is not available.', $methodCode));
            }

            $this->_verifyOrder();
        }
        return $this->_order;
    }

    /**
     * Load recurring profile
     *
     * @return Mage_Sales_Model_Recurring_Profile
     * @throws Exception
     */
    protected function _getRecurringProfile()
    {
        if (empty($this->_recurringProfile)) {
            // get proper recurring profile
            $internalReferenceId = $this->_request['rp_invoice_id'];
            $this->_recurringProfile = Mage::getModel('sales/recurring_profile')
                ->loadByInternalReferenceId($internalReferenceId);
            if (!$this->_recurringProfile->getId()) {
                throw new Exception(
                    sprintf('Wrong recurring profile INTERNAL_REFERENCE_ID: "%s".', $internalReferenceId),
                );
            }
            // re-initialize config with the method code and store id
            $methodCode = $this->_recurringProfile->getMethodCode();
            $this->_config = Mage::getModel(
                'paypal/config',
                [$methodCode, $this->_recurringProfile->getStoreId()],
            );
            if (!$this->_config->isMethodActive($methodCode) || !$this->_config->isMethodAvailable()) {
                throw new Exception(sprintf('Method "%s" is not available.', $methodCode));
            }
        }
        return $this->_recurringProfile;
    }

    /**
     * Validate incoming request data, as PayPal recommends
     *
     * @throws Exception
     * @link https://cms.paypal.com/cgi-bin/marketingweb?cmd=_render-content&content_ID=developer/e_howto_admin_IPNIntro
     */
    protected function _verifyOrder()
    {
        // verify merchant email intended to receive notification
        $merchantEmail = $this->_config->businessAccount;
        if ($merchantEmail) {
            $receiverEmail = $this->getRequestData('business');
            if (!$receiverEmail) {
                $receiverEmail = $this->getRequestData('receiver_email');
            }
            if (strtolower($merchantEmail) != strtolower($receiverEmail)) {
                throw new Exception(
                    sprintf(
                        'Requested %s and configured %s merchant emails do not match.',
                        $receiverEmail,
                        $merchantEmail,
                    ),
                );
            }
        }
    }

    /**
     * IPN workflow implementation
     * Everything should be added to order comments. In positive processing cases customer will get email notifications.
     * Admin will be notified on errors.
     */
    protected function _processOrder()
    {
        $this->_order = null;
        $this->_getOrder();

        $this->_info = Mage::getSingleton('paypal/info');
        try {
            // Handle payment_status
            $transactionType = $this->_request['txn_type'] ?? null;
            match ($transactionType) {
                Mage_Paypal_Model_Info::TXN_TYPE_NEW_CASE => $this->_registerDispute(),
                Mage_Paypal_Model_Info::TXN_TYPE_ADJUSTMENT => $this->_registerAdjustment(),
                default => $this->_registerTransaction(),
            };
        } catch (Mage_Core_Exception $e) {
            $comment = $this->_createIpnComment(Mage::helper('paypal')->__('Note: %s', $e->getMessage()), true);
            $comment->save();
            throw $e;
        }
    }

    /**
     * Process adjustment notification
     */
    protected function _registerAdjustment()
    {
        $reasonCode = $this->_request['reason_code'] ?? null;
        $reasonComment = $this->_info::explainReasonCode($reasonCode);
        $notificationAmount = $this->_order->getBaseCurrency()->formatTxt($this->_request['mc_gross']);

        // Add IPN comment about registered dispute
        $message = Mage::helper('paypal')->__('IPN "%s". A dispute has been resolved and closed. %s Transaction amount %s.', ucfirst($reasonCode), $notificationAmount, $reasonComment);
        $this->_order->addStatusHistoryComment($message)
            ->setIsCustomerNotified(false)
            ->save();
    }

    /**
     * Process dispute notification
     */
    protected function _registerDispute()
    {
        $reasonCode = $this->_request['reason_code'] ?? null;
        $reasonComment = $this->_info::explainReasonCode($reasonCode);
        $caseType = $this->_request['case_type'] ?? null;
        $caseTypeLabel = $this->_info::getCaseTypeLabel($caseType);
        $caseId = $this->_request['case_id'] ?? null;

        // Add IPN comment about registered dispute
        $message = Mage::helper('paypal')->__('IPN "%s". Case type "%s". Case ID "%s" %s', ucfirst($caseType), $caseTypeLabel, $caseId, $reasonComment);
        $this->_order->addStatusHistoryComment($message)
            ->setIsCustomerNotified(false)
            ->save();
    }

    /**
     * Process regular IPN notifications
     */
    protected function _registerTransaction()
    {
        try {
            $paymentStatus = $this->_filterPaymentStatus($this->_request['payment_status']);
            match ($paymentStatus) {
                Mage_Paypal_Model_Info::PAYMENTSTATUS_COMPLETED => $this->_registerPaymentCapture(true),
                Mage_Paypal_Model_Info::PAYMENTSTATUS_DENIED => $this->_registerPaymentDenial(),
                Mage_Paypal_Model_Info::PAYMENTSTATUS_FAILED => $this->_registerPaymentFailure(),
                Mage_Paypal_Model_Info::PAYMENTSTATUS_PENDING => $this->_registerPaymentPending(),
                Mage_Paypal_Model_Info::PAYMENTSTATUS_PROCESSED => $this->_registerMasspaymentsSuccess(),
                Mage_Paypal_Model_Info::PAYMENTSTATUS_REVERSED, Mage_Paypal_Model_Info::PAYMENTSTATUS_UNREVERSED => $this->_registerPaymentReversal(),
                Mage_Paypal_Model_Info::PAYMENTSTATUS_REFUNDED => $this->_registerPaymentRefund(),
                Mage_Paypal_Model_Info::PAYMENTSTATUS_EXPIRED, Mage_Paypal_Model_Info::PAYMENTSTATUS_VOIDED => $this->_registerPaymentVoid(),
                default => throw new Exception("Cannot handle payment status '{$paymentStatus}'."),
            };
        } catch (Mage_Core_Exception $e) {
            $comment = $this->_createIpnComment(Mage::helper('paypal')->__('Note: %s', $e->getMessage()), true);
            $comment->save();
            throw $e;
        }
    }

    /**
     * Process notification from recurring profile payments
     */
    protected function _processRecurringProfile()
    {
        $this->_recurringProfile = null;
        $this->_getRecurringProfile();

        try {
            // handle payment_status
            $paymentStatus = $this->_filterPaymentStatus($this->_request['payment_status']);

            match ($paymentStatus) {
                Mage_Paypal_Model_Info::PAYMENTSTATUS_COMPLETED => $this->_registerRecurringProfilePaymentCapture(),
                default => throw new Exception("Cannot handle payment status '{$paymentStatus}'."),
            };
        } catch (Mage_Core_Exception $e) {
            throw $e;
        }
    }

    /**
     * Register recurring payment notification, create and process order
     */
    protected function _registerRecurringProfilePaymentCapture()
    {
        $price = $this->getRequestData('mc_gross') - $this->getRequestData('tax') -  $this->getRequestData('shipping');
        $productItemInfo = new Varien_Object();
        $type = trim($this->getRequestData('period_type'));
        if ($type == 'Trial') {
            $productItemInfo->setPaymentType(Mage_Sales_Model_Recurring_Profile::PAYMENT_TYPE_TRIAL);
        } elseif ($type == 'Regular') {
            $productItemInfo->setPaymentType(Mage_Sales_Model_Recurring_Profile::PAYMENT_TYPE_REGULAR);
        }
        $productItemInfo->setTaxAmount($this->getRequestData('tax'));
        $productItemInfo->setShippingAmount($this->getRequestData('shipping'));
        $productItemInfo->setPrice($price);

        $order = $this->_recurringProfile->createOrder($productItemInfo);

        $payment = $order->getPayment();
        $payment->setTransactionId($this->getRequestData('txn_id'))
            ->setCurrencyCode($this->getRequestData('mc_currency'))
            ->setPreparedMessage($this->_createIpnComment(''))
            ->setIsTransactionClosed(0);
        $order->save();
        $this->_recurringProfile->addOrderRelation($order->getId());
        $payment->registerCaptureNotification($this->getRequestData('mc_gross'));
        $order->save();

        $invoice = $payment->getCreatedInvoice();
        if ($invoice) {
            // notify customer
            $message = Mage::helper('paypal')->__('Notified customer about invoice #%s.', $invoice->getIncrementId());
            $order->queueNewOrderEmail()->addStatusHistoryComment($message)
                ->setIsCustomerNotified(true)
                ->save();
        }
    }

    /**
     * Process completed payment (either full or partial)
     *
     * @param bool $skipFraudDetection
     */
    protected function _registerPaymentCapture($skipFraudDetection = false)
    {
        if ($this->getRequestData('transaction_entity') == 'auth') {
            return;
        }
        $parentTransactionId = $this->getRequestData('parent_txn_id');
        $this->_importPaymentInformation();
        $payment = $this->_order->getPayment();
        $payment->setTransactionId($this->getRequestData('txn_id'))
            ->setCurrencyCode($this->getRequestData('mc_currency'))
            ->setPreparedMessage($this->_createIpnComment(''))
            ->setParentTransactionId($parentTransactionId)
            ->setShouldCloseParentTransaction($this->getRequestData('auth_status') === 'Completed')
            ->setIsTransactionClosed(0)
            ->registerCaptureNotification(
                $this->getRequestData('mc_gross'),
                $skipFraudDetection && $parentTransactionId,
            );
        $this->_order->save();

        // notify customer
        $invoice = $payment->getCreatedInvoice();
        if ($invoice && !$this->_order->getEmailSent()) {
            $this->_order->queueNewOrderEmail()->addStatusHistoryComment(
                Mage::helper('paypal')->__('Notified customer about invoice #%s.', $invoice->getIncrementId()),
            )
            ->setIsCustomerNotified(true)
            ->save();
        }
    }

    /**
     * Process denied payment notification
     */
    protected function _registerPaymentDenial()
    {
        $this->_importPaymentInformation();
        /** @var Mage_Sales_Model_Order_Payment $payment */
        $payment = $this->_order->getPayment();

        $payment->setTransactionId($this->getRequestData('txn_id'))
            ->setNotificationResult(true)
            ->setIsTransactionClosed(true);
        if (!$this->_order->isCanceled()) {
            $payment->registerPaymentReviewAction(Mage_Sales_Model_Order_Payment::REVIEW_ACTION_DENY, false);
        } else {
            $transactionId = Mage::helper('paypal')->getHtmlTransactionId(
                $payment->getMethodInstance()->getCode(),
                $this->getRequestData('txn_id'),
            );
            $comment = Mage::helper('paypal')->__('Transaction ID: "%s"', $transactionId);
            $this->_order->addStatusHistoryComment($this->_createIpnComment($comment), false);
        }

        $this->_order->save();
    }

    /**
     * Treat failed payment as order cancellation
     */
    protected function _registerPaymentFailure()
    {
        $this->_importPaymentInformation();

        foreach ($this->_order->getInvoiceCollection() as $invoice) {
            $invoice->cancel()->save();
        }

        $this->_order
            ->registerCancellation($this->_createIpnComment(''), false)
            ->save();
    }

    /**
     * Process a refund or a chargeback
     */
    protected function _registerPaymentRefund()
    {
        $this->_importPaymentInformation();
        $reason = $this->getRequestData('reason_code');
        $isRefundFinal = !$this->_info::isReversalDisputable($reason);

        /** @var Mage_Sales_Model_Order_Payment $payment */
        $payment = $this->_order->getPayment();

        $amount = $this->_order->getBaseCurrency()->formatTxt($payment->getBaseAmountRefundedOnline());

        $transactionId = Mage::helper('paypal')->getHtmlTransactionId(
            $payment->getMethodInstance()->getCode(),
            $this->getRequestData('txn_id'),
        );
        $comment = $this->_createIpnComment($this->_info::explainReasonCode($reason))
            . ' '
            . Mage::helper('paypal')->__('Refunded amount of %s. Transaction ID: "%s"', $amount, $transactionId);

        $payment->setPreparedMessage($comment)
            ->setTransactionId($this->getRequestData('txn_id'))
            ->setParentTransactionId($this->getRequestData('parent_txn_id'))
            ->setIsTransactionClosed($isRefundFinal)
            ->registerRefundNotification(-1 * (float) $this->getRequestData('mc_gross'));
        $this->_order->addStatusHistoryComment($comment, false);
        $this->_order->save();

        // TODO: there is no way to close a capture right now
        $creditmemo = $payment->getCreatedCreditmemo();
        if ($creditmemo) {
            $creditmemo->sendEmail();
            $this->_order->addStatusHistoryComment(
                Mage::helper('paypal')->__('Notified customer about creditmemo #%s.', $creditmemo->getIncrementId()),
            )
            ->setIsCustomerNotified(true)
            ->save();
        }
    }

    /**
     * Process payment reversal and cancelled reversal notification
     */
    protected function _registerPaymentReversal()
    {
        $reasonCode = $this->_request['reason_code'] ?? null;
        $reasonComment = $this->_info::explainReasonCode($reasonCode);
        $notificationAmount = $this->_order
            ->getBaseCurrency()
            ->formatTxt($this->_request['mc_gross'] + $this->_request['mc_fee']);
        $paymentStatus = $this->_filterPaymentStatus($this->_request['payment_status'] ?? null);
        $orderStatus = ($paymentStatus == Mage_Paypal_Model_Info::PAYMENTSTATUS_REVERSED)
            ? Mage_Paypal_Model_Info::ORDER_STATUS_REVERSED
            : Mage_Paypal_Model_Info::ORDER_STATUS_CANCELED_REVERSAL;
        /**
         * Change order status to PayPal Reversed/PayPal Cancelled Reversal if it is possible.
         */
        $transactionId = Mage::helper('paypal')->getHtmlTransactionId(
            $this->_config->getMethodCode(),
            $this->_request['txn_id'],
        );
        $message = Mage::helper('paypal')->__('IPN "%s". %s Transaction amount %s. Transaction ID: "%s"', $this->_request['payment_status'], $reasonComment, $notificationAmount, $transactionId);
        $this->_order->setStatus($orderStatus);
        $this->_order->save();
        $this->_order->addStatusHistoryComment($message, $orderStatus)
            ->setIsCustomerNotified(false)
            ->save();
    }

    /**
     * Process payment pending notification
     *
     * @throws Exception
     */
    public function _registerPaymentPending()
    {
        $reason = $this->getRequestData('pending_reason');
        if ($reason === 'authorization') {
            $this->_registerPaymentAuthorization();
            return;
        }
        if ($reason === 'order') {
            throw new Exception('The "order" authorizations are not implemented.');
        }

        // case when was placed using PayPal standard
        if (Mage_Sales_Model_Order::STATE_PENDING_PAYMENT == $this->_order->getState()
            && !$this->getRequestData('transaction_entity')
        ) {
            $this->_registerPaymentCapture();
            return;
        }

        $this->_importPaymentInformation();

        $this->_order->getPayment()
            ->setPreparedMessage($this->_createIpnComment($this->_info::explainPendingReason($reason)))
            ->setTransactionId($this->getRequestData('txn_id'))
            ->setIsTransactionClosed(0)
            ->registerPaymentReviewAction(Mage_Sales_Model_Order_Payment::REVIEW_ACTION_UPDATE, false);
        $this->_order->save();
    }

    /**
     * Register authorized payment
     */
    protected function _registerPaymentAuthorization()
    {
        $this->_importPaymentInformation();

        $this->_order->getPayment()
            ->setPreparedMessage($this->_createIpnComment(''))
            ->setTransactionId($this->getRequestData('txn_id'))
            ->setParentTransactionId($this->getRequestData('parent_txn_id'))
            ->setCurrencyCode($this->getRequestData('mc_currency'))
            ->setIsTransactionClosed(0)
            ->registerAuthorizationNotification($this->getRequestData('mc_gross'));

        if (!$this->_order->getEmailSent()) {
            $this->_order->queueNewOrderEmail();
        }
        $this->_order->save();
    }

    /**
     * Process voided authorization
     */
    protected function _registerPaymentVoid()
    {
        $this->_importPaymentInformation();

        $parentTxnId = $this->getRequestData('transaction_entity') == 'auth'
            ? $this->getRequestData('txn_id') : $this->getRequestData('parent_txn_id');

        $this->_order->getPayment()
            ->setPreparedMessage($this->_createIpnComment(''))
            ->setParentTransactionId($parentTxnId)
            ->registerVoidNotification();

        $this->_order->save();
    }

    /**
     * TODO
     * The status "Processed" is used when all Masspayments are successful
     */
    protected function _registerMasspaymentsSuccess()
    {
        $comment = $this->_createIpnComment('', true);
        $comment->save();
    }

    /**
     * Generate an "IPN" comment with additional explanation.
     * Returns the generated comment or order status history object
     *
     * @param string $comment
     * @param bool $addToHistory
     * @return string|Mage_Sales_Model_Order_Status_History
     */
    protected function _createIpnComment($comment = '', $addToHistory = false)
    {
        $paymentStatus = $this->getRequestData('payment_status');
        $message = Mage::helper('paypal')->__('IPN "%s".', $paymentStatus);
        if ($comment) {
            $message .= ' ' . $comment;
        }
        if ($addToHistory) {
            $message = $this->_order->addStatusHistoryComment($message);
            $message->setIsCustomerNotified(null);
        }
        return $message;
    }

    /**
     * Map payment information from IPN to payment object
     * Returns true if there were changes in information
     *
     * @return bool
     */
    protected function _importPaymentInformation()
    {
        $payment = $this->_order->getPayment();
        $was = $payment->getAdditionalInformation();

        // collect basic information
        $from = [];
        foreach ([
            Mage_Paypal_Model_Info::PAYER_ID,
            'payer_email' => Mage_Paypal_Model_Info::PAYER_EMAIL,
            Mage_Paypal_Model_Info::PAYER_STATUS,
            Mage_Paypal_Model_Info::ADDRESS_STATUS,
            Mage_Paypal_Model_Info::PROTECTION_EL,
            Mage_Paypal_Model_Info::PAYMENT_STATUS,
            Mage_Paypal_Model_Info::PENDING_REASON,
        ] as $privateKey => $publicKey
        ) {
            if (is_int($privateKey)) {
                $privateKey = $publicKey;
            }
            $value = $this->getRequestData($privateKey);
            if ($value) {
                $from[$publicKey] = $value;
            }
        }
        if (isset($from['payment_status'])) {
            $from['payment_status'] = $this->_filterPaymentStatus($this->getRequestData('payment_status'));
        }

        // collect fraud filters
        $fraudFilters = [];
        for ($i = 1; $value = $this->getRequestData("fraud_management_pending_filters_{$i}"); $i++) {
            $fraudFilters[] = $value;
        }
        if ($fraudFilters) {
            $from[Mage_Paypal_Model_Info::FRAUD_FILTERS] = $fraudFilters;
        }

        $this->_info->importToPayment($from, $payment);

        /**
         * Detect pending payment, frauds
         * TODO: implement logic in one place
         * @see Mage_Paypal_Model_Pro::importPaymentInfo()
         */
        if ($this->_info::isPaymentReviewRequired($payment)) {
            $payment->setIsTransactionPending(true);
            if ($fraudFilters) {
                $payment->setIsFraudDetected(true);
            }
        }
        if ($this->_info::isPaymentSuccessful($payment)) {
            $payment->setIsTransactionApproved(true);
        } elseif ($this->_info::isPaymentFailed($payment)) {
            $payment->setIsTransactionDenied(true);
        }

        return $was != $payment->getAdditionalInformation();
    }

    /**
     * Filter payment status from NVP into paypal/info format
     *
     * @param string $ipnPaymentStatus
     * @return string
     */
    protected function _filterPaymentStatus($ipnPaymentStatus)
    {
        return match ($ipnPaymentStatus) {
            'Created', 'Completed' => Mage_Paypal_Model_Info::PAYMENTSTATUS_COMPLETED,
            'Denied' => Mage_Paypal_Model_Info::PAYMENTSTATUS_DENIED,
            'Expired' => Mage_Paypal_Model_Info::PAYMENTSTATUS_EXPIRED,
            'Failed' => Mage_Paypal_Model_Info::PAYMENTSTATUS_FAILED,
            'Pending' => Mage_Paypal_Model_Info::PAYMENTSTATUS_PENDING,
            'Refunded' => Mage_Paypal_Model_Info::PAYMENTSTATUS_REFUNDED,
            'Reversed' => Mage_Paypal_Model_Info::PAYMENTSTATUS_REVERSED,
            'Canceled_Reversal' => Mage_Paypal_Model_Info::PAYMENTSTATUS_UNREVERSED,
            'Processed' => Mage_Paypal_Model_Info::PAYMENTSTATUS_PROCESSED,
            'Voided' => Mage_Paypal_Model_Info::PAYMENTSTATUS_VOIDED,
            default => '',
        };
        // documented in NVP, but not documented in IPN:
        //Mage_Paypal_Model_Info::PAYMENTSTATUS_NONE
        //Mage_Paypal_Model_Info::PAYMENTSTATUS_INPROGRESS
        //Mage_Paypal_Model_Info::PAYMENTSTATUS_REFUNDEDPART
    }

    /**
     * Log debug data to file
     */
    protected function _debug()
    {
        if ($this->_config && $this->_config->debug) {
            $file = $this->_config->getMethodCode() ? "payment_{$this->_config->getMethodCode()}.log"
                : self::DEFAULT_LOG_FILE;
            Mage::getModel('core/log_adapter', $file)->log($this->_debugData);
        }
    }
}
