<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Newsletter_ProblemController extends Mage_Adminhtml_Controller_Action
{
    /**
     * ACL resource
     * @see Mage_Adminhtml_Controller_Action::_isAllowed()
     */
    public const ADMIN_RESOURCE = 'newsletter/problem';

    public function indexAction()
    {
        $this->_title($this->__('Newsletter'))->_title($this->__('Newsletter Problems'));

        if ($this->getRequest()->getQuery('ajax')) {
            $this->_forward('grid');
            return;
        }

        $this->getLayout()->getMessagesBlock()->setMessages(
            Mage::getSingleton('adminhtml/session')->getMessages(true),
        );
        $this->loadLayout();

        $this->_setActiveMenu('newsletter/problem');

        $this->_addBreadcrumb(Mage::helper('newsletter')->__('Newsletter Problem Reports'), Mage::helper('newsletter')->__('Newsletter Problem Reports'));

        $this->_addContent(
            $this->getLayout()->createBlock('adminhtml/newsletter_problem', 'problem'),
        );

        $this->renderLayout();
    }

    public function gridAction()
    {
        if ($this->getRequest()->getParam('_unsubscribe')) {
            $problems = (array) $this->getRequest()->getParam('problem', []);
            if (count($problems) > 0) {
                $collection = Mage::getResourceModel('newsletter/problem_collection');
                $collection
                    ->addSubscriberInfo()
                    ->addFieldToFilter(
                        $collection->getResource()->getIdFieldName(),
                        ['in' => $problems],
                    )
                    ->load();

                $collection->walk('unsubscribe');
            }

            Mage::getSingleton('adminhtml/session')
                ->addSuccess(Mage::helper('newsletter')->__('Selected problem subscribers have been unsubscribed.'));
        }

        if ($this->getRequest()->getParam('_delete')) {
            $problems = (array) $this->getRequest()->getParam('problem', []);
            if (count($problems) > 0) {
                $collection = Mage::getResourceModel('newsletter/problem_collection');
                $collection
                    ->addFieldToFilter(
                        $collection->getResource()->getIdFieldName(),
                        ['in' => $problems],
                    )
                    ->load();
                $collection->walk('delete');
            }

            Mage::getSingleton('adminhtml/session')
                ->addSuccess(Mage::helper('newsletter')->__('Selected problems have been deleted.'));
        }
        $this->getLayout()->getMessagesBlock()->setMessages(Mage::getSingleton('adminhtml/session')->getMessages(true));

        $grid = $this->getLayout()->createBlock('adminhtml/newsletter_problem_grid');
        $this->getResponse()->setBody($grid->toHtml());
    }
}
