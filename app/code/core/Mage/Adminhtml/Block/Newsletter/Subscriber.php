<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Newsletter_Subscriber extends Mage_Adminhtml_Block_Template
{
    /**
     * @var Mage_Newsletter_Model_Resource_Queue_Collection|null
     */
    protected $_queueCollection = null;

    public function __construct()
    {
        $this->setTemplate('newsletter/subscriber/list.phtml');
    }

    /**
     * Prepares block to render
     *
     * @return $this
     */
    #[\Override]
    protected function _beforeToHtml()
    {
        $this->setChild('grid', $this->getLayout()->createBlock('adminhtml/newsletter_subscriber_grid', 'grid'));
        return parent::_beforeToHtml();
    }

    /**
     * Return queue collection with loaded neversent queues
     *
     * @return Mage_Newsletter_Model_Resource_Queue_Collection
     */
    public function getQueueCollection()
    {
        if (is_null($this->_queueCollection)) {
            $this->_queueCollection = Mage::getResourceSingleton('newsletter/queue_collection')
                ->addTemplateInfo()
                ->addOnlyUnsentFilter()
                ->load();
        }

        return $this->_queueCollection;
    }

    public function getShowQueueAdd()
    {
        return $this->getChild('grid')->getShowQueueAdd();
    }

    /**
     * Return list of neversent queues for select
     *
     * @return array
     */
    public function getQueueAsOptions()
    {
        return $this->getQueueCollection()->toOptionArray();
    }
}
