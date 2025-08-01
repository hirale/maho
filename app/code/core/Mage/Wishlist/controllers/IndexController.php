<?php

/**
 * Maho
 *
 * @package    Mage_Wishlist
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2025 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method float getQty()
 * @method int getProductId()
 */
class Mage_Wishlist_IndexController extends Mage_Wishlist_Controller_Abstract
{
    /**
     * Action list where need check enabled cookie
     *
     * @var array
     */
    protected $_cookieCheckActions = ['add'];

    /**
     * If true, authentication in this controller (wishlist) could be skipped
     *
     * @var bool
     */
    protected $_skipAuthentication = false;

    /**
     * Extend preDispatch
     *
     * @return $this|void
     */
    #[\Override]
    public function preDispatch()
    {
        parent::preDispatch();

        if (!$this->_skipAuthentication && !Mage::getSingleton('customer/session')->authenticate($this)) {
            $this->setFlag('', 'no-dispatch', true);
            if (!Mage::getSingleton('customer/session')->getBeforeWishlistUrl()) {
                Mage::getSingleton('customer/session')->setBeforeWishlistUrl($this->_getRefererUrl());
            }
            Mage::getSingleton('customer/session')->setBeforeWishlistRequest($this->getRequest()->getParams());
        }
        if (!Mage::getStoreConfigFlag('wishlist/general/active')) {
            $this->norouteAction();
            return;
        }
        return $this;
    }

    /**
     * Set skipping authentication in actions of this controller (wishlist)
     *
     * @return $this
     */
    public function skipAuthentication()
    {
        $this->_skipAuthentication = true;
        return $this;
    }

    /**
     * Retrieve wishlist object
     * @param int $wishlistId
     * @return Mage_Wishlist_Model_Wishlist|false
     */
    #[\Override]
    protected function _getWishlist($wishlistId = null)
    {
        $wishlist = Mage::registry('wishlist');
        if ($wishlist) {
            return $wishlist;
        }

        try {
            if (!$wishlistId) {
                $wishlistId = $this->getRequest()->getParam('wishlist_id');
            }
            $customerId = Mage::getSingleton('customer/session')->getCustomerId();
            $wishlist = Mage::getModel('wishlist/wishlist');
            if ($wishlistId) {
                $wishlist->load($wishlistId);
            } else {
                $wishlist->loadByCustomer($customerId, true);
            }

            if (!$wishlist->getId() || $wishlist->getCustomerId() != $customerId) {
                $wishlist = null;
                Mage::throwException(
                    Mage::helper('wishlist')->__("Requested wishlist doesn't exist"),
                );
            }

            Mage::register('wishlist', $wishlist);
        } catch (Mage_Core_Exception $e) {
            Mage::getSingleton('wishlist/session')->addError($e->getMessage());
            return false;
        } catch (Exception $e) {
            Mage::getSingleton('wishlist/session')->addException(
                $e,
                Mage::helper('wishlist')->__('Wishlist could not be created.'),
            );
            return false;
        }

        return $wishlist;
    }

    /**
     * Display customer wishlist
     *
     * @return Mage_Core_Controller_Varien_Action|void
     */
    public function indexAction()
    {
        if (!$this->_getWishlist()) {
            $this->norouteAction();
            return;
        }
        $this->loadLayout();

        if (strpos($this->_getRefererUrl(), 'login')) {
            Mage::getSingleton('core/session')->addError(Mage::helper('wishlist')->__(
                'Please add product to wishlist again.',
            ));
            return $this->_redirectUrl(Mage::getSingleton('customer/session')->getBeforeWishlistUrl());
        }

        $session = Mage::getSingleton('customer/session');
        $block   = $this->getLayout()->getBlock('customer.wishlist');
        $referer = $session->getAddActionReferer(true);
        if ($block) {
            $block->setRefererUrl($this->_getRefererUrl());
            if ($referer) {
                $block->setRefererUrl($referer);
            }
        }

        $this->_initLayoutMessages('customer/session');
        $this->_initLayoutMessages('checkout/session');
        $this->_initLayoutMessages('catalog/session');
        $this->_initLayoutMessages('wishlist/session');

        $this->renderLayout();
    }

    /**
     * Adding new item
     *
     * @return Mage_Core_Controller_Varien_Action|void
     */
    public function addAction()
    {
        if (!$this->_validateFormKey()) {
            return $this->_redirect('*/*');
        }
        $this->_addItemToWishList();
    }

    /**
     * Add the item to wish list
     *
     * @return void
     * @throws Throwable
     */
    protected function _addItemToWishList()
    {
        $wishlist = $this->_getWishlist();
        if (!$wishlist) {
            $this->norouteAction();
            return;
        }

        $session = Mage::getSingleton('customer/session');

        $productId = (int) $this->getRequest()->getParam('product');
        if (!$productId) {
            $this->_redirect('*/');
            return;
        }

        $product = Mage::getModel('catalog/product')->load($productId);
        if (!$product->getId() || !$product->isVisibleInCatalog()) {
            $session->addError($this->__('Cannot specify product.'));
            $this->_redirect('*/');
            return;
        }

        try {
            $requestParams = $this->getRequest()->getParams();
            if ($session->getBeforeWishlistRequest()) {
                $requestParams = $session->getBeforeWishlistRequest();
                $session->unsBeforeWishlistRequest();
            }
            $buyRequest = new Varien_Object($requestParams);

            $result = $wishlist->addNewItem($product, $buyRequest);
            if (is_string($result)) {
                Mage::throwException($result);
            }
            $wishlist->save();

            Mage::dispatchEvent(
                'wishlist_add_product',
                [
                    'wishlist' => $wishlist,
                    'product' => $product,
                    'item' => $result,
                ],
            );

            $referer = $session->getBeforeWishlistUrl();
            if ($referer) {
                $session->setBeforeWishlistUrl(null);
            } else {
                $referer = $this->_getRefererUrl();
            }

            /**
             *  Set referer to avoid referring to the compare popup window
             */
            $session->setAddActionReferer($referer);

            Mage::helper('wishlist')->calculate();

            $message = $this->__(
                '%1$s has been added to your wishlist. Click <a href="%2$s">here</a> to continue shopping.',
                $product->getName(),
                Mage::helper('core')->escapeUrl($referer),
            );
            $session->addSuccess($message);
        } catch (Mage_Core_Exception $e) {
            $session->addError($this->__('An error occurred while adding item to wishlist: %s', $e->getMessage()));
        } catch (Exception $e) {
            $session->addError($this->__('An error occurred while adding item to wishlist.'));
        }

        $this->_redirect('*', ['wishlist_id' => $wishlist->getId()]);
    }

    /**
     * Action to reconfigure wishlist item
     *
     * @return void
     */
    public function configureAction()
    {
        $id = (int) $this->getRequest()->getParam('id');
        try {
            /** @var Mage_Wishlist_Model_Item $item */
            $item = Mage::getModel('wishlist/item');
            $item->loadWithOptions($id);
            if (!$item->getId()) {
                Mage::throwException($this->__('Cannot load wishlist item'));
            }
            $wishlist = $this->_getWishlist($item->getWishlistId());
            if (!$wishlist) {
                $this->norouteAction();
                return;
            }

            Mage::register('wishlist_item', $item);

            $params = new Varien_Object();
            $params->setCategoryId(false);
            $params->setConfigureMode(true);
            $buyRequest = $item->getBuyRequest();
            if (!$buyRequest->getQty() && $item->getQty()) {
                $buyRequest->setQty($item->getQty());
            }
            if ($buyRequest->getQty() && !$item->getQty()) {
                $item->setQty($buyRequest->getQty());
                Mage::helper('wishlist')->calculate();
            }
            $params->setBuyRequest($buyRequest);
            Mage::helper('catalog/product_view')->prepareAndRender($item->getProductId(), $this, $params);
        } catch (Mage_Core_Exception $e) {
            Mage::getSingleton('customer/session')->addError($e->getMessage());
            $this->_redirect('*');
            return;
        } catch (Exception $e) {
            Mage::getSingleton('customer/session')->addError($this->__('Cannot configure product'));
            Mage::logException($e);
            $this->_redirect('*');
            return;
        }
    }

    /**
     * Action to accept new configuration for a wishlist item
     */
    public function updateItemOptionsAction()
    {
        $session = Mage::getSingleton('customer/session');
        $productId = (int) $this->getRequest()->getParam('product');
        if (!$productId) {
            $this->_redirect('*/');
            return;
        }

        $product = Mage::getModel('catalog/product')->load($productId);
        if (!$product->getId() || !$product->isVisibleInCatalog()) {
            $session->addError($this->__('Cannot specify product.'));
            $this->_redirect('*/');
            return;
        }

        try {
            $id = (int) $this->getRequest()->getParam('id');
            /** @var Mage_Wishlist_Model_Item $item */
            $item = Mage::getModel('wishlist/item');
            $item->load($id);
            $wishlist = $this->_getWishlist($item->getWishlistId());
            if (!$wishlist) {
                $this->_redirect('*/');
                return;
            }

            $buyRequest = new Varien_Object($this->getRequest()->getPost());
            $buyRequest->unsFormKey();

            $wishlist
                ->updateItem($item->getId(), $buyRequest)
                ->save();

            Mage::helper('wishlist')->calculate();
            Mage::dispatchEvent('wishlist_update_item', [
                'wishlist' => $wishlist, 'product' => $product, 'item' => $wishlist->getItemById($id)]);

            Mage::helper('wishlist')->calculate();

            $message = $this->__('%1$s has been updated in your wishlist.', $product->getName());
            $session->addSuccess($message);
        } catch (Mage_Core_Exception $e) {
            $session->addError($e->getMessage());
        } catch (Exception $e) {
            $session->addError($this->__('An error occurred while updating wishlist.'));
            Mage::logException($e);
        }
        $this->_redirect('*/*', ['wishlist_id' => $wishlist->getId()]);
    }

    /**
     * Update wishlist item comments
     *
     * @return Mage_Core_Controller_Varien_Action|void
     */
    public function updateAction()
    {
        if (!$this->_validateFormKey()) {
            return $this->_redirect('*/*/');
        }
        $wishlist = $this->_getWishlist();
        if (!$wishlist) {
            $this->norouteAction();
            return;
        }

        $post = $this->getRequest()->getPost();
        if ($post && isset($post['description']) && is_array($post['description'])) {
            $updatedItems = 0;

            foreach ($post['description'] as $itemId => $description) {
                $item = Mage::getModel('wishlist/item')->load($itemId);
                if ($item->getWishlistId() != $wishlist->getId()) {
                    continue;
                }

                // Extract new values
                $description = (string) $description;

                if ($description == Mage::helper('wishlist')->defaultCommentString()) {
                    $description = '';
                } elseif (!strlen($description)) {
                    $description = $item->getDescription();
                }

                $qty = null;
                if (isset($post['qty'][$itemId])) {
                    $qty = $this->_processLocalizedQty($post['qty'][$itemId]);
                }
                if (is_null($qty)) {
                    $qty = $item->getQty();
                    if (!$qty) {
                        $qty = 1;
                    }
                } elseif ($qty == 0) {
                    try {
                        $item->delete();
                    } catch (Exception $e) {
                        Mage::logException($e);
                        Mage::getSingleton('customer/session')->addError(
                            $this->__('Can\'t delete item from wishlist'),
                        );
                    }
                }

                // Check that we need to save
                if (($item->getDescription() == $description) && ($item->getQty() == $qty)) {
                    continue;
                }
                try {
                    $item->setDescription($description)
                        ->setQty($qty)
                        ->save();
                    $updatedItems++;
                } catch (Exception $e) {
                    Mage::getSingleton('customer/session')->addError(
                        $this->__('Can\'t save description %s', Mage::helper('core')->escapeHtml($description)),
                    );
                }
            }

            // save wishlist model for setting date of last update
            if ($updatedItems) {
                try {
                    $wishlist->save();
                    Mage::helper('wishlist')->calculate();
                } catch (Exception $e) {
                    Mage::getSingleton('customer/session')->addError($this->__('Can\'t update wishlist'));
                }
            }

            if (isset($post['save_and_share'])) {
                $this->_redirect('*/*/share', ['wishlist_id' => $wishlist->getId()]);
                return;
            }
        }
        $this->_redirect('*', ['wishlist_id' => $wishlist->getId()]);
    }

    /**
     * Remove item
     *
     *  @return Mage_Core_Controller_Varien_Action|void
     */
    public function removeAction()
    {
        if (!$this->_validateFormKey()) {
            return $this->_redirect('*/*');
        }
        $id = (int) $this->getRequest()->getParam('item');
        $item = Mage::getModel('wishlist/item')->load($id);
        if (!$item->getId()) {
            $this->norouteAction();
            return;
        }
        $wishlist = $this->_getWishlist($item->getWishlistId());
        if (!$wishlist) {
            $this->norouteAction();
            return;
        }
        try {
            $item->delete();
            $wishlist->save();
        } catch (Mage_Core_Exception $e) {
            Mage::getSingleton('customer/session')->addError(
                $this->__('An error occurred while deleting the item from wishlist: %s', $e->getMessage()),
            );
        } catch (Exception $e) {
            Mage::getSingleton('customer/session')->addError(
                $this->__('An error occurred while deleting the item from wishlist.'),
            );
        }

        Mage::helper('wishlist')->calculate();

        $this->_redirectReferer(Mage::getUrl('*/*'));
    }

    /**
     * Add wishlist item to shopping cart and remove from wishlist
     *
     * If Product has required options - item removed from wishlist and redirect
     * to product view page with message about needed defined required options
     */
    public function cartAction()
    {
        if (!$this->_validateFormKey()) {
            return $this->_redirect('*/*');
        }
        $itemId = (int) $this->getRequest()->getParam('item');

        /** @var Mage_Wishlist_Model_Item $item */
        $item = Mage::getModel('wishlist/item')->load($itemId);
        if (!$item->getId()) {
            return $this->_redirect('*/*');
        }
        $wishlist = $this->_getWishlist($item->getWishlistId());
        if (!$wishlist) {
            return $this->_redirect('*/*');
        }

        // Set qty
        $qty = $this->getRequest()->getParam('qty');
        if (is_array($qty)) {
            $qty = $qty[$itemId] ?? 1;
        }
        $qty = (float) $qty;
        if ($qty && $qty > 0) {
            $item->setQty($qty);
        }

        /** @var Mage_Wishlist_Model_Session $session */
        $session    = Mage::getSingleton('wishlist/session');
        $cart       = Mage::getSingleton('checkout/cart');

        $redirectUrl = Mage::getUrl('*/*');

        try {
            $options = Mage::getModel('wishlist/item_option')->getCollection()
                    ->addItemFilter([$itemId]);
            $item->setOptions($options->getOptionsByItem($itemId));

            $buyRequest = Mage::helper('catalog/product')->addParamsToBuyRequest(
                $this->getRequest()->getParams(),
                ['current_config' => $item->getBuyRequest()],
            );

            $item->mergeBuyRequest($buyRequest);
            if ($item->addToCart($cart, true)) {
                $cart->save()->getQuote()->collectTotals();
            }

            $wishlist->save();
            Mage::helper('wishlist')->calculate();

            if (Mage::helper('checkout/cart')->getShouldRedirectToCart()) {
                $redirectUrl = Mage::helper('checkout/cart')->getCartUrl();
            }
            Mage::helper('wishlist')->calculate();

            $product = Mage::getModel('catalog/product')
                ->setStoreId(Mage::app()->getStore()->getId())
                ->load($item->getProductId());
            $productName = Mage::helper('core')->escapeHtml($product->getName());
            $message = $this->__('%s was added to your shopping cart.', $productName);
            Mage::getSingleton('catalog/session')->addSuccess($message);
        } catch (Mage_Core_Exception $e) {
            if ($e->getCode() == Mage_Wishlist_Model_Item::EXCEPTION_CODE_NOT_SALABLE) {
                $session->addError($this->__('This product(s) is currently out of stock'));
            } elseif ($e->getCode() == Mage_Wishlist_Model_Item::EXCEPTION_CODE_HAS_REQUIRED_OPTIONS) {
                Mage::getSingleton('catalog/session')->addNotice($e->getMessage());
                $redirectUrl = Mage::getUrl('*/*/configure/', ['id' => $item->getId()]);
            } else {
                Mage::getSingleton('catalog/session')->addNotice($e->getMessage());
                $redirectUrl = Mage::getUrl('*/*/configure/', ['id' => $item->getId()]);
            }
        } catch (Exception $e) {
            Mage::logException($e);
            $session->addException($e, $this->__('Cannot add item to shopping cart'));
        }

        Mage::helper('wishlist')->calculate();

        return $this->_redirectUrl($redirectUrl);
    }

    /**
     * Add cart item to wishlist and remove from cart
     *
     * @return Mage_Core_Controller_Varien_Action|void
     */
    public function fromcartAction()
    {
        $wishlist = $this->_getWishlist();
        if (!$wishlist) {
            $this->norouteAction();
            return;
        }
        $itemId = (int) $this->getRequest()->getParam('item');

        /** @var Mage_Checkout_Model_Cart $cart */
        $cart = Mage::getSingleton('checkout/cart');
        $session = Mage::getSingleton('checkout/session');

        try {
            $item = $cart->getQuote()->getItemById($itemId);
            if (!$item) {
                Mage::throwException(
                    Mage::helper('wishlist')->__("Requested cart item doesn't exist"),
                );
            }

            $productId  = $item->getProductId();
            $buyRequest = $item->getBuyRequest();

            // Check if product has file options and clean them from buy request
            $product = $item->getProduct();
            $hasFileOptions = false;
            $options = $product->getOptions();
            if ($options) {
                foreach ($options as $option) {
                    if ($option->getType() === Mage_Catalog_Model_Product_Option::OPTION_TYPE_FILE) {
                        $hasFileOptions = true;
                        // Remove file option data from buy request
                        if ($buyRequest->hasOptions()) {
                            $requestOptions = $buyRequest->getOptions();
                            if (isset($requestOptions[$option->getId()])) {
                                unset($requestOptions[$option->getId()]);
                                $buyRequest->setOptions($requestOptions);
                            }
                        }
                    }
                }
            }

            $wishlist->addNewItem($productId, $buyRequest);

            $cart->getQuote()->removeItem($itemId);
            $cart->save();
            Mage::helper('wishlist')->calculate();
            $productName = Mage::helper('core')->escapeHtml($item->getProduct()->getName());
            $wishlistName = Mage::helper('core')->escapeHtml($wishlist->getName());

            // Add appropriate success message
            if ($hasFileOptions) {
                $session->addSuccess(
                    Mage::helper('wishlist')->__('%s has been moved to wishlist %s. Please note that uploaded files will need to be re-uploaded when adding to cart.', $productName, $wishlistName),
                );
            } else {
                $session->addSuccess(
                    Mage::helper('wishlist')->__('%s has been moved to wishlist %s', $productName, $wishlistName),
                );
            }

            $wishlist->save();
        } catch (Mage_Core_Exception $e) {
            $session->addError($e->getMessage());
        } catch (Exception $e) {
            $session->addException($e, Mage::helper('wishlist')->__('Cannot move item to wishlist'));
        }

        return $this->_redirectUrl(Mage::helper('checkout/cart')->getCartUrl());
    }

    /**
     * Prepare wishlist for share
     */
    public function shareAction()
    {
        $this->_getWishlist();
        $this->loadLayout();
        $this->_initLayoutMessages('customer/session');
        $this->_initLayoutMessages('wishlist/session');
        $this->renderLayout();
    }

    /**
     * Share wishlist
     *
     * @return Mage_Core_Controller_Varien_Action|void
     */
    public function sendAction()
    {
        if (!$this->_validateFormKey()) {
            return $this->_redirect('*/*/');
        }

        $wishlist = $this->_getWishlist();
        if (!$wishlist) {
            $this->norouteAction();
            return;
        }

        $emails  = array_filter(explode(',', $this->getRequest()->getPost('emails', '')));
        $message = nl2br(htmlspecialchars((string) $this->getRequest()->getPost('message')));
        $error   = false;
        if (empty($emails)) {
            $error = $this->__('Email address can\'t be empty.');
        } elseif (count($emails) > 5) {
            $error = $this->__('Please enter no more than 5 email addresses.');
        } else {
            foreach ($emails as $index => $email) {
                $email = trim($email);
                if (!Zend_Validate::is($email, 'EmailAddress')) {
                    $error = $this->__('Please input a valid email address.');
                    break;
                }
                $emails[$index] = $email;
            }
        }
        if ($error) {
            Mage::getSingleton('wishlist/session')->addError($error);
            Mage::getSingleton('wishlist/session')->setSharingForm($this->getRequest()->getPost());
            $this->_redirect('*/*/share');
            return;
        }

        $translate = Mage::getSingleton('core/translate');
        /** @var Mage_Core_Model_Translate $translate */
        $translate->setTranslateInline(false);

        try {
            $customer = Mage::getSingleton('customer/session')->getCustomer();

            /*if share rss added rss feed to email template*/
            if ($this->getRequest()->getParam('rss_url')) {
                $rssUrl = $this->getLayout()
                    ->createBlock('wishlist/share_email_rss')
                    ->setWishlistId($wishlist->getId())
                    ->toHtml();
                $message .= $rssUrl;
            }
            $wishlistBlock = $this->getLayout()->createBlock('wishlist/share_email_items')->toHtml();

            $emails = array_unique($emails);
            /** @var Mage_Core_Model_Email_Template $emailModel */
            $emailModel = Mage::getModel('core/email_template');

            $sharingCode = $wishlist->getSharingCode();
            foreach ($emails as $email) {
                $emailModel->sendTransactional(
                    Mage::getStoreConfig('wishlist/email/email_template'),
                    Mage::getStoreConfig('wishlist/email/email_identity'),
                    $email,
                    null,
                    [
                        'customer'       => $customer,
                        'salable'        => $wishlist->isSalable() ? 'yes' : '',
                        'items'          => $wishlistBlock,
                        'addAllLink'     => Mage::getUrl('*/shared/allcart', ['code' => $sharingCode]),
                        'viewOnSiteLink' => Mage::getUrl('*/shared/index', ['code' => $sharingCode]),
                        'message'        => $message,
                    ],
                );
            }

            $wishlist->setShared(1);
            $wishlist->save();

            $translate->setTranslateInline(true);

            Mage::dispatchEvent('wishlist_share', ['wishlist' => $wishlist]);
            Mage::getSingleton('customer/session')->addSuccess(
                $this->__('Your Wishlist has been shared.'),
            );
            $this->_redirect('*/*', ['wishlist_id' => $wishlist->getId()]);
        } catch (Exception $e) {
            $translate->setTranslateInline(true);

            Mage::getSingleton('wishlist/session')->addError($e->getMessage());
            Mage::getSingleton('wishlist/session')->setSharingForm($this->getRequest()->getPost());
            $this->_redirect('*/*/share');
        }
    }

    /**
     * Custom options download action
     * @return void
     */
    public function downloadCustomOptionAction()
    {
        $option = Mage::getModel('wishlist/item_option')->load($this->getRequest()->getParam('id'));

        if (!$option->getId()) {
            $this->_forward('noRoute');
            return;
        }

        $optionId = null;
        if (str_starts_with($option->getCode(), Mage_Catalog_Model_Product_Type_Abstract::OPTION_PREFIX)) {
            $optionId = str_replace(Mage_Catalog_Model_Product_Type_Abstract::OPTION_PREFIX, '', $option->getCode());
            if (!is_numeric($optionId)) {
                $this->_forward('noRoute');
                return;
            }
        }
        $productOption = Mage::getModel('catalog/product_option')->load($optionId);

        if (!$productOption
            || !$productOption->getId()
            || $productOption->getProductId() != $option->getProductId()
            || $productOption->getType() != 'file'
        ) {
            $this->_forward('noRoute');
            return;
        }

        try {
            $info      = unserialize($option->getValue(), ['allowed_classes' => false]);
            $filePath  = Mage::getBaseDir() . $info['quote_path'];
            $secretKey = $this->getRequest()->getParam('key');

            if ($secretKey == $info['secret_key']) {
                $this->_prepareDownloadResponse($info['title'], [
                    'value' => $filePath,
                    'type'  => 'filename',
                ]);
            }
        } catch (Exception $e) {
            $this->_forward('noRoute');
        }
        exit(0);
    }
}
