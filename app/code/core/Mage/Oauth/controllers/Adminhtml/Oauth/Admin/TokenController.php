<?php

/**
 * Maho
 *
 * @package    Mage_Oauth
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Manage "My Applications" controller
 *
 * Applications for logged admin user
 */
class Mage_Oauth_Adminhtml_Oauth_Admin_TokenController extends Mage_Adminhtml_Controller_Action
{
    /**
     * Init titles
     *
     * @return $this
     */
    #[\Override]
    public function preDispatch()
    {
        $this->_title($this->__('System'))
                ->_title($this->__('Permissions'))
                ->_title($this->__('My Applications'));
        parent::preDispatch();
        return $this;
    }

    /**
     * Render grid page
     */
    public function indexAction()
    {
        $this
            ->loadLayout()
            ->_setActiveMenu('system/api/oauth_admin_token')
            ->renderLayout();
    }

    /**
     * Render grid AJAX request
     */
    public function gridAction()
    {
        $this->loadLayout();
        $this->renderLayout();
    }

    /**
     * Update revoke status action
     */
    public function revokeAction()
    {
        $ids = $this->getRequest()->getParam('items');
        $status = $this->getRequest()->getParam('status');

        if (!is_array($ids) || !$ids) {
            // No rows selected
            $this->_getSession()->addError($this->__('Please select needed row(s).'));
            $this->_redirect('*/*/index');
            return;
        }

        if ($status === null) {
            // No status selected
            $this->_getSession()->addError($this->__('Please select revoke status.'));
            $this->_redirect('*/*/index');
            return;
        }

        try {
            /** @var Mage_Admin_Model_User $user */
            $user = Mage::getSingleton('admin/session')->getData('user');

            /** @var Mage_Oauth_Model_Resource_Token_Collection $collection */
            $collection = Mage::getModel('oauth/token')->getCollection();
            $collection->joinConsumerAsApplication()
                    ->addFilterByAdminId($user->getId())
                    ->addFilterByType(Mage_Oauth_Model_Token::TYPE_ACCESS)
                    ->addFilterById($ids)
                    ->addFilterByRevoked(!$status);

            /** @var Mage_Oauth_Model_Token $item */
            foreach ($collection as $item) {
                $item->load($item->getId());
                $item->setRevoked($status)->save();
            }
            if ($status) {
                $message = $this->__('Selected entries revoked.');
            } else {
                $message = $this->__('Selected entries enabled.');
            }
            $this->_getSession()->addSuccess($message);
        } catch (Mage_Core_Exception $e) {
            $this->_getSession()->addError($e->getMessage());
        } catch (Exception $e) {
            $this->_getSession()->addError($this->__('An error occurred on update revoke status.'));
            Mage::logException($e);
        }
        $this->_redirect('*/*/index');
    }

    /**
     * Delete action
     */
    public function deleteAction()
    {
        $ids = $this->getRequest()->getParam('items');

        if (!is_array($ids) || !$ids) {
            // No rows selected
            $this->_getSession()->addError($this->__('Please select needed row(s).'));
            $this->_redirect('*/*/index');
            return;
        }

        try {
            /** @var Mage_Admin_Model_User $user */
            $user = Mage::getSingleton('admin/session')->getData('user');

            /** @var Mage_Oauth_Model_Resource_Token_Collection $collection */
            $collection = Mage::getModel('oauth/token')->getCollection();
            $collection->joinConsumerAsApplication()
                    ->addFilterByAdminId($user->getId())
                    ->addFilterByType(Mage_Oauth_Model_Token::TYPE_ACCESS)
                    ->addFilterById($ids);

            /** @var Mage_Oauth_Model_Token $item */
            foreach ($collection as $item) {
                $item->delete();
            }
            $this->_getSession()->addSuccess($this->__('Selected entries has been deleted.'));
        } catch (Mage_Core_Exception $e) {
            $this->_getSession()->addError($e->getMessage());
        } catch (Exception $e) {
            $this->_getSession()->addError($this->__('An error occurred on delete action.'));
            Mage::logException($e);
        }
        $this->_redirect('*/*/index');
    }

    #[\Override]
    protected function _isAllowed()
    {
        /** @var Mage_Admin_Model_Session $session */
        $session = Mage::getSingleton('admin/session');
        return $session->isAllowed('system/api/oauth_admin_token');
    }
}
