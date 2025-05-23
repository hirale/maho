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

class Mage_Adminhtml_Block_System_Store_Delete extends Mage_Adminhtml_Block_Widget_Form_Container
{
    /**
     * Class constructor
     */
    public function __construct()
    {
        $this->_objectId = 'item_id';
        $this->_mode = 'delete';
        $this->_controller = 'system_store';

        parent::__construct();

        $this->_removeButton('save');
        $this->_removeButton('reset');

        $this->_updateButton('delete', 'area', 'footer');
        $this->_updateButton('delete', 'onclick', 'editForm.submit();');

        $this->_addButton('cancel', [
            'label'     => Mage::helper('adminhtml')->__('Cancel'),
            'onclick'   => Mage::helper('core/js')->getSetLocationJs($this->getBackUrl()),
        ], 2, 100, 'footer');
    }

    /**
     * Get edit form container header text
     *
     * @return string
     */
    #[\Override]
    public function getHeaderText()
    {
        return Mage::helper('adminhtml')->__(
            "Delete %s '%s'",
            $this->getStoreTypeTitle(),
            $this->escapeHtml($this->getChild('form')->getDataObject()->getName()),
        );
    }

    /**
     * Set store type title
     *
     * @param string $title
     * @return $this
     */
    public function setStoreTypeTitle($title)
    {
        $this->_updateButton('delete', 'label', Mage::helper('adminhtml')->__('Delete %s', $title));
        return $this->setData('store_type_title', $title);
    }

    /**
     * Set back URL for "Cancel" and "Back" buttons
     *
     * @param string $url
     * @return $this
     */
    public function setBackUrl($url)
    {
        $this->setData('back_url', $url);
        $this->_updateButton('cancel', 'onclick', Mage::helper('core/js')->getSetLocationJs($url));
        $this->_updateButton('back', 'onclick', Mage::helper('core/js')->getSetLocationJs($url));
        return $this;
    }
}
