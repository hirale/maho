<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */


class Mage_Adminhtml_Block_Cache extends Mage_Adminhtml_Block_Widget_Grid_Container
{
    /**
     * Class constructor
     */
    public function __construct()
    {
        $this->_controller = 'cache';
        $this->_headerText = Mage::helper('core')->__('Cache Storage Management');
        parent::__construct();
        $this->_removeButton('add');
        $this->_addButton('flush_magento', [
            'label'     => Mage::helper('core')->__('Flush & Apply Updates'),
            'onclick'   => Mage::helper('core/js')->getSetLocationJs($this->getFlushSystemUrl()),
            'class'     => 'delete',
        ]);

        $this->_addButton('flush_system', [
            'label'     => Mage::helper('core')->__('Flush Cache Storage'),
            'onclick'   => Mage::helper('core/js')->getConfirmSetLocationJs(
                $this->getFlushStorageUrl(),
                Mage::helper('core')->__('Cache storage may contain additional data. Are you sure that you want flush it?'),
            ),
            'class'     => 'delete',
        ]);
    }

    /**
     * Get url for clean cache storage
     *
     * @return string
     */
    public function getFlushStorageUrl()
    {
        return $this->getUrl('*/*/flushAll');
    }

    /**
     * Get url for clean cache storage
     *
     * @return string
     */
    public function getFlushSystemUrl()
    {
        return $this->getUrl('*/*/flushSystem');
    }
}
