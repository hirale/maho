<?php

/**
 * Maho
 *
 * @package    Mage_Sales
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Sales_Model_Observer
{
    /**
     * Expire quotes additional fields to filter
     *
     * @var array
     */
    protected $_expireQuotesFilterFields = [];

    /**
     * Clean expired quotes (cron process)
     *
     * @return $this
     * @throws Mage_Core_Exception
     */
    public function cleanExpiredQuotes()
    {
        Mage::dispatchEvent('clear_expired_quotes_before', ['sales_observer' => $this]);
        $lifetimes = Mage::getConfig()->getStoresConfigByPath('checkout/cart/delete_quote_after');

        foreach ($lifetimes as $storeId => $day) {
            $day = (int) $day;
            $lifetime = 86400 * $day;

            /** @var Mage_Sales_Model_Resource_Quote_Collection $quotes */
            $quotes = Mage::getResourceModel('sales/quote_collection');
            $quotes->addFieldToFilter('store_id', $storeId);
            $quotes->addFieldToFilter('updated_at', ['to' => date('Y-m-d', time() - $lifetime)]);
            if ($day == 0) {
                $quotes->addFieldToFilter('is_active', 0);
            }

            foreach ($this->getExpireQuotesAdditionalFilterFields() as $field => $condition) {
                $quotes->addFieldToFilter($field, $condition);
            }

            foreach ($quotes as $quote) {
                $quote->delete();
            }
        }

        return $this;
    }

    /**
     * Retrieve expire quotes additional fields to filter
     *
     * @return array
     */
    public function getExpireQuotesAdditionalFilterFields()
    {
        return $this->_expireQuotesFilterFields;
    }

    /**
     * Set expire quotes additional fields to filter
     *
     * @return $this
     */
    public function setExpireQuotesAdditionalFilterFields(array $fields)
    {
        $this->_expireQuotesFilterFields = $fields;
        return $this;
    }

    /**
     * When deleting product, subtract it from all quotes quantities
     *
     * @throws Exception
     * @return $this
     */
    public function substractQtyFromQuotes(Varien_Event_Observer $observer)
    {
        /** @var Mage_Catalog_Model_Product $product */
        $product = $observer->getEvent()->getProduct();
        Mage::getResourceSingleton('sales/quote')->substractProductFromQuotes($product);
        return $this;
    }

    /**
     * When applying a catalog price rule, make related quotes recollect on demand
     *
     * @return $this
     */
    public function markQuotesRecollectOnCatalogRules(Varien_Event_Observer $observer)
    {
        /** @var Mage_Catalog_Model_Product $product */
        $product = $observer->getEvent()->getProduct();

        if (is_numeric($product)) {
            $product = Mage::getModel('catalog/product')->load($product);
        }
        if ($product instanceof Mage_Catalog_Model_Product) {
            $childrenProductList = Mage::getSingleton('catalog/product_type')->factory($product)
                ->getChildrenIds($product->getId(), false);

            $productIdList = [$product->getId()];
            foreach ($childrenProductList as $groupData) {
                $productIdList = array_merge($productIdList, $groupData);
            }
        } else {
            $productIdList = null;
        }

        Mage::getResourceSingleton('sales/quote')->markQuotesRecollectByAffectedProduct($productIdList);
        return $this;
    }

    /**
     * Catalog Product After Save (change status process)
     *
     * @return $this
     */
    public function catalogProductSaveAfter(Varien_Event_Observer $observer)
    {
        /** @var Mage_Catalog_Model_Product $product */
        $product = $observer->getEvent()->getProduct();
        if ($product->getStatus() == Mage_Catalog_Model_Product_Status::STATUS_ENABLED) {
            return $this;
        }

        Mage::getResourceSingleton('sales/quote')->markQuotesRecollect($product->getId());

        return $this;
    }

    /**
     * Catalog Mass Status update process
     *
     * @return $this
     */
    public function catalogProductStatusUpdate(Varien_Event_Observer $observer)
    {
        $status     = $observer->getEvent()->getStatus();
        if ($status == Mage_Catalog_Model_Product_Status::STATUS_ENABLED) {
            return $this;
        }
        $productId  = $observer->getEvent()->getProductId();
        Mage::getResourceSingleton('sales/quote')->markQuotesRecollect($productId);

        return $this;
    }

    /**
     * Refresh sales order report statistics for last day
     *
     * @return $this
     */
    public function aggregateSalesReportOrderData()
    {
        Mage::app()->getLocale()->emulate(0);
        $currentDate = Mage::app()->getLocale()->date();
        $date = $currentDate->subHour(25);
        Mage::getResourceModel('sales/report_order')->aggregate($date);
        Mage::app()->getLocale()->revert();
        return $this;
    }

    /**
     * Refresh sales shipment report statistics for last day
     *
     * @return $this
     * @throws Zend_Date_Exception
     */
    public function aggregateSalesReportShipmentData()
    {
        Mage::app()->getLocale()->emulate(0);
        $currentDate = Mage::app()->getLocale()->date();
        $date = $currentDate->subHour(25);
        Mage::getResourceModel('sales/report_shipping')->aggregate($date);
        Mage::app()->getLocale()->revert();
        return $this;
    }

    /**
     * Refresh sales invoiced report statistics for last day
     *
     * @return $this
     * @throws Zend_Date_Exception
     */
    public function aggregateSalesReportInvoicedData()
    {
        Mage::app()->getLocale()->emulate(0);
        $currentDate = Mage::app()->getLocale()->date();
        $date = $currentDate->subHour(25);
        Mage::getResourceModel('sales/report_invoiced')->aggregate($date);
        Mage::app()->getLocale()->revert();
        return $this;
    }

    /**
     * Refresh sales refunded report statistics for last day
     *
     * @return $this
     * @throws Zend_Date_Exception
     */
    public function aggregateSalesReportRefundedData()
    {
        Mage::app()->getLocale()->emulate(0);
        $currentDate = Mage::app()->getLocale()->date();
        $date = $currentDate->subHour(25);
        Mage::getResourceModel('sales/report_refunded')->aggregate($date);
        Mage::app()->getLocale()->revert();
        return $this;
    }

    /**
     * Refresh bestsellers report statistics for last day
     *
     * @return $this
     * @throws Zend_Date_Exception
     */
    public function aggregateSalesReportBestsellersData()
    {
        Mage::app()->getLocale()->emulate(0);
        $currentDate = Mage::app()->getLocale()->date();
        $date = $currentDate->subHour(25);
        Mage::getResourceModel('sales/report_bestsellers')->aggregate($date);
        Mage::app()->getLocale()->revert();
        return $this;
    }

    /**
     * Add the recurring profile form when editing a product
     *
     * @param Varien_Event_Observer $observer
     */
    public function prepareProductEditFormRecurringProfile($observer)
    {
        // replace the element of recurring payment profile field with a form
        $profileElement = $observer->getEvent()->getProductElement();
        $block = Mage::app()->getLayout()->createBlock(
            'sales/adminhtml_recurring_profile_edit_form',
            'adminhtml_recurring_profile_edit_form',
        )->setParentElement($profileElement)
            ->setProductEntity($observer->getEvent()->getProduct());
        $observer->getEvent()->getResult()->output = $block->toHtml();

        // make the profile element dependent on is_recurring
        /** @var Mage_Adminhtml_Block_Widget_Form_Element_Dependence $block */
        $block = Mage::app()->getLayout()->createBlock(
            'adminhtml/widget_form_element_dependence',
            'adminhtml_recurring_profile_edit_form_dependence',
        );
        $dependencies = $block
            ->addFieldMap('is_recurring', 'product[is_recurring]')
            ->addFieldMap($profileElement->getHtmlId(), $profileElement->getName())
            ->addFieldDependence($profileElement->getName(), 'product[is_recurring]', '1');
        $observer->getEvent()->getResult()->output .= $dependencies->toHtml();
    }

    /**
     * Block admin ability to use customer billing agreements
     *
     * @param Varien_Event_Observer $observer
     */
    public function restrictAdminBillingAgreementUsage($observer)
    {
        $methodInstance = $observer->getEvent()->getMethodInstance();
        if (!($methodInstance instanceof Mage_Sales_Model_Payment_Method_Billing_AgreementAbstract)) {
            return;
        }
        if (!Mage::getSingleton('admin/session')->isAllowed('sales/billing_agreement/actions/use')) {
            $observer->getEvent()->getResult()->isAvailable = false;
        }
    }

    /**
     * Set new customer group to all his quotes
     *
     * @return $this
     */
    public function customerSaveAfter(Varien_Event_Observer $observer)
    {
        /** @var Mage_Customer_Model_Customer $customer */
        $customer = $observer->getEvent()->getCustomer();

        if ($customer->getGroupId() !== $customer->getOrigData('group_id')) {
            /**
             * It is needed to process customer's quotes for all websites
             * if customer accounts are shared between all of them
             */
            $websites = (Mage::getSingleton('customer/config_share')->isWebsiteScope())
                ? [Mage::app()->getWebsite($customer->getWebsiteId())]
                : Mage::app()->getWebsites();

            /** @var Mage_Sales_Model_Quote $quote */
            $quote = Mage::getSingleton('sales/quote');

            foreach ($websites as $website) {
                $quote->setWebsite($website);
                $quote->loadByCustomer($customer);

                if ($quote->getId()) {
                    $quote->setCustomerGroupId($customer->getGroupId());
                    $quote->collectTotals();
                    $quote->save();
                }
            }
        }

        return $this;
    }

    /**
     * Set Quote information about MSRP price enabled
     */
    public function setQuoteCanApplyMsrp(Varien_Event_Observer $observer)
    {
        /** @var Mage_Sales_Model_Quote $quote */
        $quote = $observer->getEvent()->getQuote();

        $canApplyMsrp = false;
        if (Mage::helper('catalog')->isMsrpEnabled()) {
            foreach ($quote->getAllAddresses() as $adddress) {
                if ($adddress->getCanApplyMsrp()) {
                    $canApplyMsrp = true;
                    break;
                }
            }
        }

        $quote->setCanApplyMsrp($canApplyMsrp);
    }

    /**
     * Add VAT validation request date and identifier to order comments
     */
    public function addVatRequestParamsOrderComment(Varien_Event_Observer $observer)
    {
        /** @var Mage_Sales_Model_Order $orderInstance */
        $orderInstance = $observer->getOrder();
        /** @var Mage_Sales_Model_Order_Address $orderAddress */
        $orderAddress = $this->_getVatRequiredSalesAddress($orderInstance);
        if (!($orderAddress instanceof Mage_Sales_Model_Order_Address)) {
            return;
        }

        $vatRequestId = $orderAddress->getVatRequestId();
        $vatRequestDate = $orderAddress->getVatRequestDate();
        if (is_string($vatRequestId) && !empty($vatRequestId) && is_string($vatRequestDate)
            && !empty($vatRequestDate)
        ) {
            $orderHistoryComment = Mage::helper('customer')->__('VAT Request Identifier')
                . ': ' . $vatRequestId . '<br />' . Mage::helper('customer')->__('VAT Request Date')
                . ': ' . $vatRequestDate;
            $orderInstance->addStatusHistoryComment($orderHistoryComment, false);
        }
    }

    /**
     * Retrieve sales address (order or quote) on which tax calculation must be based
     *
     * @param Mage_Core_Model_Abstract $salesModel
     * @param Mage_Core_Model_Store|string|int|null $store
     * @return Mage_Customer_Model_Address_Abstract|null
     */
    protected function _getVatRequiredSalesAddress($salesModel, $store = null)
    {
        $configAddressType = Mage::helper('customer/address')->getTaxCalculationAddressType($store);
        $requiredAddress = null;
        $requiredAddress = match ($configAddressType) {
            Mage_Customer_Model_Address_Abstract::TYPE_SHIPPING => $salesModel->getShippingAddress(),
            default => $salesModel->getBillingAddress(),
        };
        return $requiredAddress;
    }

    /**
     * Retrieve customer address (default billing or default shipping) ID on which tax calculation must be based
     *
     * @param Mage_Core_Model_Store|string|int|null $store
     * @return int|string
     */
    protected function _getVatRequiredCustomerAddress(Mage_Customer_Model_Customer $customer, $store = null)
    {
        $configAddressType = Mage::helper('customer/address')->getTaxCalculationAddressType($store);
        $requiredAddress = null;
        $requiredAddress = match ($configAddressType) {
            Mage_Customer_Model_Address_Abstract::TYPE_SHIPPING => $customer->getDefaultShipping(),
            default => $customer->getDefaultBilling(),
        };
        return $requiredAddress;
    }

    /**
     * Handle customer VAT number if needed on collect_totals_before event of quote address
     */
    public function changeQuoteCustomerGroupId(Varien_Event_Observer $observer)
    {
        $addressHelper = Mage::helper('customer/address');

        /** @var Mage_Sales_Model_Quote_Address $quoteAddress */
        $quoteAddress = $observer->getQuoteAddress();
        /** @var Mage_Sales_Model_Quote $quoteInstance */
        $quoteInstance = $quoteAddress->getQuote();
        $customerInstance = $quoteInstance->getCustomer();
        $isDisableAutoGroupChange = $customerInstance->getDisableAutoGroupChange();

        $storeId = $customerInstance->getStore();

        $configAddressType = Mage::helper('customer/address')->getTaxCalculationAddressType($storeId);

        // When VAT is based on billing address then Maho have to handle only billing addresses
        $additionalBillingAddressCondition = ($configAddressType == Mage_Customer_Model_Address_Abstract::TYPE_BILLING)
            ? $configAddressType != $quoteAddress->getAddressType() : false;
        // Handle only addresses that corresponds to VAT configuration
        if (!$addressHelper->isVatValidationEnabled($storeId) || $additionalBillingAddressCondition) {
            return;
        }

        $customerHelper = Mage::helper('customer');

        $customerCountryCode = $quoteAddress->getCountryId();
        $customerVatNumber = $quoteAddress->getVatId();

        if ((empty($customerVatNumber) || !Mage::helper('core')->isCountryInEU($customerCountryCode))
            && !$isDisableAutoGroupChange
        ) {
            $groupId = ($customerInstance->getId()) ? $customerHelper->getDefaultCustomerGroupId($storeId)
                : Mage_Customer_Model_Group::NOT_LOGGED_IN_ID;

            $quoteAddress->setPrevQuoteCustomerGroupId($quoteInstance->getCustomerGroupId());
            $customerInstance->setGroupId($groupId);
            $quoteInstance->setCustomerGroupId($groupId);

            return;
        }

        /** @var Mage_Core_Helper_Data $coreHelper */
        $coreHelper = Mage::helper('core');
        $merchantCountryCode = $coreHelper->getMerchantCountryCode();
        $merchantVatNumber = $coreHelper->getMerchantVatNumber();

        $gatewayResponse = null;
        if ($addressHelper->getValidateOnEachTransaction($storeId)
            || $customerCountryCode != $quoteAddress->getValidatedCountryCode()
            || $customerVatNumber != $quoteAddress->getValidatedVatNumber()
        ) {
            // Send request to gateway
            $gatewayResponse = $customerHelper->checkVatNumber(
                $customerCountryCode,
                $customerVatNumber,
                ($merchantVatNumber !== '') ? $merchantCountryCode : '',
                $merchantVatNumber,
            );

            // Store validation results in corresponding quote address
            $quoteAddress->setVatIsValid((int) $gatewayResponse->getIsValid())
                ->setVatRequestId($gatewayResponse->getRequestIdentifier())
                ->setVatRequestDate($gatewayResponse->getRequestDate())
                ->setVatRequestSuccess($gatewayResponse->getRequestSuccess())
                ->setValidatedVatNumber($customerVatNumber)
                ->setValidatedCountryCode($customerCountryCode)
                ->save();
        } else {
            // Restore validation results from corresponding quote address
            $gatewayResponse = new Varien_Object([
                'is_valid' => (int) $quoteAddress->getVatIsValid(),
                'request_identifier' => (string) $quoteAddress->getVatRequestId(),
                'request_date' => (string) $quoteAddress->getVatRequestDate(),
                'request_success' => (bool) $quoteAddress->getVatRequestSuccess(),
            ]);
        }

        // Maho always has to emulate a group even if a customer uses default billing/shipping address.
        if (!$isDisableAutoGroupChange) {
            $groupId = $customerHelper->getCustomerGroupIdBasedOnVatNumber(
                $customerCountryCode,
                $gatewayResponse,
                $customerInstance->getStore(),
            );
        } else {
            $groupId = $quoteInstance->getCustomerGroupId();
        }

        if ($groupId) {
            $quoteAddress->setPrevQuoteCustomerGroupId($quoteInstance->getCustomerGroupId());
            $customerInstance->setGroupId($groupId);
            $quoteInstance->setCustomerGroupId($groupId);
        }
    }

    /**
     * Restore initial customer group ID in quote if needed on collect_totals_after event of quote address
     *
     * @param Varien_Event_Observer $observer
     */
    public function restoreQuoteCustomerGroupId($observer)
    {
        /** @var Mage_Sales_Model_Quote_Address $quoteAddress */
        $quoteAddress = $observer->getQuoteAddress();
        $configAddressType = Mage::helper('customer/address')->getTaxCalculationAddressType();
        // Restore initial customer group ID in quote only if VAT is calculated based on shipping address
        if ($quoteAddress->hasPrevQuoteCustomerGroupId()
            && $configAddressType == Mage_Customer_Model_Address_Abstract::TYPE_SHIPPING
        ) {
            $quoteAddress->getQuote()->setCustomerGroupId($quoteAddress->getPrevQuoteCustomerGroupId());
            $quoteAddress->unsPrevQuoteCustomerGroupId();
        }
    }
}
