<?php

/**
 * Maho
 *
 * @package    Mage_Checkout
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Shopping cart item render block
 *
 * @package    Mage_Checkout
 *
 * @method bool hasProductName()
 * @method $this setProductName(string $value)
 * @method bool hasDeleteUrl()
 * @method $this setDeleteUrl(string $value)
 * @method string getIdSuffix()
 */
class Mage_Checkout_Block_Cart_Item_Renderer extends Mage_Core_Block_Template
{
    /** @var Mage_Checkout_Model_Session */
    protected $_checkoutSession;
    protected $_item;
    protected $_productUrl = null;
    protected $_productThumbnail = null;

    /**
     * Whether qty will be converted to number
     *
     * @var bool
     */
    protected $_strictQtyMode = true;

    /**
     * Check, whether product URL rendering should be ignored
     *
     * @var bool
     */
    protected $_ignoreProductUrl = false;

    /**
     * Set item for render
     *
     * @return  $this
     */
    public function setItem(Mage_Sales_Model_Quote_Item_Abstract $item)
    {
        $this->_item = $item;
        return $this;
    }

    /**
     * Get quote item
     *
     * @return Mage_Sales_Model_Quote_Item
     */
    public function getItem()
    {
        return $this->_item;
    }

    /**
     * Get item product
     *
     * @return Mage_Catalog_Model_Product
     */
    public function getProduct()
    {
        return $this->getItem()->getProduct();
    }

    /**
     * @param Mage_Catalog_Helper_Image $productThumbnail
     * @return $this
     */
    public function overrideProductThumbnail($productThumbnail)
    {
        $this->_productThumbnail = $productThumbnail;
        return $this;
    }

    /**
     * Get product thumbnail image
     *
     * @return Mage_Catalog_Helper_Image
     */
    public function getProductThumbnail()
    {
        if (!is_null($this->_productThumbnail)) {
            return $this->_productThumbnail;
        }

        /** @var Mage_Catalog_Helper_Image $helper */
        $helper = $this->helper('catalog/image');
        return $helper->init($this->getProduct(), 'thumbnail');
    }

    /**
     * @param string $productUrl
     * @return $this
     */
    public function overrideProductUrl($productUrl)
    {
        $this->_productUrl = $productUrl;
        return $this;
    }

    /**
     * Check Product has URL
     *
     * @return bool
     */
    public function hasProductUrl()
    {
        if ($this->_ignoreProductUrl) {
            return false;
        }
        if ($this->_productUrl || $this->getItem()->getRedirectUrl()) {
            return true;
        }

        $product = $this->getProduct();
        $option  = $this->getItem()->getOptionByCode('product_type');
        if ($option) {
            $product = $option->getProduct();
        }
        if ($product->isVisibleInSiteVisibility()) {
            return true;
        }
        return false;
    }

    /**
     * Retrieve URL to item Product
     *
     * @return string
     */
    public function getProductUrl()
    {
        if (!is_null($this->_productUrl)) {
            return $this->_productUrl;
        }
        if ($this->getItem()->getRedirectUrl()) {
            return $this->getItem()->getRedirectUrl();
        }

        $product = $this->getProduct();
        $option  = $this->getItem()->getOptionByCode('product_type');
        if ($option) {
            $product = $option->getProduct();
        }

        return $product->getUrlModel()->getUrl($product);
    }

    /**
     * Get item product name
     *
     * @return string
     */
    public function getProductName()
    {
        if ($this->hasProductName()) {
            return $this->getData('product_name');
        }
        return $this->getProduct()->getName();
    }

    /**
     * Get product customize options
     *
     * @return array | false
     */
    public function getProductOptions()
    {
        /** @var Mage_Catalog_Helper_Product_Configuration $helper */
        $helper = Mage::helper('catalog/product_configuration');
        return $helper->getCustomOptions($this->getItem());
    }

    /**
     * Get list of all options for product
     *
     * @return array
     */
    public function getOptionList()
    {
        return $this->getProductOptions();
    }

    /**
     * Get item configure url
     *
     * @return string
     */
    public function getConfigureUrl()
    {
        return $this->getUrl(
            'checkout/cart/configure',
            ['id' => $this->getItem()->getId()],
        );
    }

    /**
     * Get item delete url
     *
     * @return string
     */
    public function getDeleteUrl()
    {
        return $this->getDeleteUrlCustom();
    }

    /**
     * Get item delete url with or without Form Key
     *
     * @param bool $addFormKey
     * @return string
     */
    public function getDeleteUrlCustom($addFormKey = true)
    {
        if ($this->hasDeleteUrl()) {
            return $this->getData('delete_url');
        }

        /** @var Mage_Core_Helper_Url $helper */
        $helper = $this->helper('core/url');

        $params = [
            'id' => $this->getItem()->getId(),
            Mage_Core_Controller_Front_Action::PARAM_NAME_URL_ENCODED => $helper->getEncodedUrl(),
        ];
        if ($addFormKey) {
            $params[Mage_Core_Model_Url::FORM_KEY] = Mage::getSingleton('core/session')->getFormKey();
        }

        return $this->getUrl('checkout/cart/delete', $params);
    }

    /**
     * Get item ajax delete url
     *
     * @return string
     * @throws Mage_Core_Model_Store_Exception
     */
    public function getAjaxDeleteUrl()
    {
        /** @var Mage_Core_Helper_Url $helper */
        $helper = $this->helper('core/url');
        return $this->getUrl(
            'checkout/cart/ajaxDelete',
            [
                'id' => $this->getItem()->getId(),
                Mage_Core_Controller_Front_Action::PARAM_NAME_URL_ENCODED => $helper->getEncodedUrl(),
                '_secure' => Mage::app()->isCurrentlySecure(),
            ],
        );
    }

    /**
     * Get item ajax update url
     *
     * @return string
     * @throws Mage_Core_Model_Store_Exception
     */
    public function getAjaxUpdateUrl()
    {
        /** @var Mage_Core_Helper_Url $helper */
        $helper = $this->helper('core/url');
        return $this->getUrl(
            'checkout/cart/ajaxUpdate',
            [
                'id' => $this->getItem()->getId(),
                Mage_Core_Controller_Front_Action::PARAM_NAME_URL_ENCODED => $helper->getEncodedUrl(),
                '_secure' => Mage::app()->isCurrentlySecure(),
            ],
        );
    }
    /**
     * Get quote item qty
     *
     * @return float|int|string
     */
    public function getQty()
    {
        if (!$this->_strictQtyMode && (string) $this->getItem()->getQty() == '') {
            return '';
        }
        return $this->getItem()->getQty() * 1;
    }

    /**
     * Check item is in stock
     *
     * @deprecated after 1.4.2.0-beta1
     * @return bool
     */
    public function getIsInStock()
    {
        if ($this->getItem()->getProduct()->isSaleable()) {
            if ($this->getItem()->getProduct()->getStockItem()->getQty() >= $this->getItem()->getQty()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get checkout session
     *
     * @return Mage_Checkout_Model_Session
     */
    public function getCheckoutSession()
    {
        if ($this->_checkoutSession === null) {
            $this->_checkoutSession = Mage::getSingleton('checkout/session');
        }
        return $this->_checkoutSession;
    }

    /**
     * Retrieve item messages
     * Return array with keys
     *
     * text => the message text
     * type => type of a message
     *
     * @return array
     */
    public function getMessages()
    {
        $messages = [];
        $quoteItem = $this->getItem();

        // Add basic messages occurring during this page load
        $baseMessages = $quoteItem->getMessage(false);
        if ($baseMessages) {
            foreach ($baseMessages as $message) {
                $messages[] = [
                    'text' => $message,
                    'type' => $quoteItem->getHasError() ? 'error' : 'notice',
                ];
            }
        }

        // Add messages saved previously in checkout session
        $checkoutSession = $this->getCheckoutSession();
        if ($checkoutSession) {
            /** @var Mage_Core_Model_Message_Collection $collection */
            $collection = $checkoutSession->getQuoteItemMessages($quoteItem->getId(), true);
            if ($collection) {
                $additionalMessages = $collection->getItems();
                foreach ($additionalMessages as $message) {
                    /** @var Mage_Core_Model_Message_Abstract $message */
                    $messages[] = [
                        'text' => $message->getCode(),
                        'type' => ($message->getType() === Mage_Core_Model_Message::ERROR) ? 'error' : 'notice',
                    ];
                }
            }
        }

        return $messages;
    }

    /**
     * Accept option value and return its formatted view
     *
     * @param mixed $optionValue
     * Method works well with these $optionValue format:
     *      1. String
     *      2. Indexed array e.g. array(val1, val2, ...)
     *      3. Associative array, containing additional option info, including option value, e.g.
     *          array
     *          (
     *              [label] => ...,
     *              [value] => ...,
     *              [print_value] => ...,
     *              [option_id] => ...,
     *              [option_type] => ...,
     *              [custom_view] =>...,
     *          )
     *
     * @return array
     */
    public function getFormatedOptionValue($optionValue)
    {
        /** @var Mage_Catalog_Helper_Product_Configuration $helper */
        $helper = Mage::helper('catalog/product_configuration');
        $params = [
            'max_length' => 55,
            'cut_replacer' => ' <a href="#" class="dots" onclick="return false">...</a>',
        ];
        return $helper->getFormattedOptionValue($optionValue, $params);
    }

    /**
     * Check whether Product is visible in site
     *
     * @return bool
     */
    public function isProductVisible()
    {
        return $this->getProduct()->isVisibleInSiteVisibility();
    }

    /**
     * Return product additional information block
     *
     * @return Mage_Core_Block_Abstract
     */
    public function getProductAdditionalInformationBlock()
    {
        return $this->getLayout()->getBlock('additional.product.info');
    }

    /**
     * Get html for MAP product enabled
     *
     * @param Mage_Sales_Model_Quote_Item $item
     * @return string
     */
    public function getMsrpHtml($item)
    {
        return $this->getLayout()->createBlock('catalog/product_price')
            ->setTemplate('catalog/product/price_msrp_item.phtml')
            ->setProduct($item->getProduct())
            ->toHtml();
    }

    /**
     * Set qty mode to be strict or not
     *
     * @param bool $strict
     * @return $this
     */
    public function setQtyMode($strict)
    {
        $this->_strictQtyMode = $strict;
        return $this;
    }

    /**
     * Set ignore product URL rendering
     *
     * @param bool $ignore
     * @return $this
     */
    public function setIgnoreProductUrl($ignore = true)
    {
        $this->_ignoreProductUrl = $ignore;
        return $this;
    }

    /**
     * Common code to be called by product renders of gift registry to create a block, which is be used to
     * generate html for mrsp price
     *
     * @param Mage_Catalog_Model_Product $product
     * @return Mage_Catalog_Block_Product_Price
     */
    protected function _preparePriceBlock($product)
    {
        return $this->getLayout()
            ->createBlock('catalog/product_price')
            ->setTemplate('catalog/product/price.phtml')
            ->setIdSuffix($this->getIdSuffix())
            ->setProduct($product);
    }

    /**
     *  Common code to be called by product renders of gift registry to  generate final html block
     *
     * @param Mage_Catalog_Model_Product $product
     * @return string
     */
    protected function _getPriceContent($product)
    {
        return $this->getLayout()->createBlock('catalog/product_price')
            ->setTemplate('catalog/product/price_msrp.phtml')
            ->setProduct($product)
            ->toHtml();
    }

    /**
     * Retrieve block cache tags
     *
     * @return array
     */
    #[\Override]
    public function getCacheTags()
    {
        $tags = $this->getProduct()->getCacheIdTags();
        $tags = is_array($tags) ? $tags : [];

        return array_merge(parent::getCacheTags(), $tags);
    }

    /**
     * Returns true if user is going through checkout process now.
     *
     * @return bool
     * @throws Exception
     */
    public function isOnCheckoutPage()
    {
        $module = $this->getRequest()->getModuleName();
        $controller = $this->getRequest()->getControllerName();
        return $module === 'checkout' && ($controller === 'onepage' || $controller === 'multishipping');
    }
}
