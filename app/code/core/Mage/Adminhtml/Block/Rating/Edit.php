<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Rating_Edit extends Mage_Adminhtml_Block_Widget_Form_Container
{
    public function __construct()
    {
        parent::__construct();
        $this->_objectId = 'id';
        $this->_controller = 'rating';

        $this->_updateButton('save', 'label', Mage::helper('rating')->__('Save Rating'));
        $this->_updateButton('delete', 'label', Mage::helper('rating')->__('Delete Rating'));

        if ($this->getRequest()->getParam($this->_objectId)) {
            $ratingData = Mage::getModel('rating/rating')
                ->load($this->getRequest()->getParam($this->_objectId));

            Mage::register('rating_data', $ratingData);
        }
    }

    /**
     * @return string
     */
    #[\Override]
    public function getHeaderText()
    {
        if (Mage::registry('rating_data') && Mage::registry('rating_data')->getId()) {
            return Mage::helper('rating')->__('Edit Rating', $this->escapeHtml(Mage::registry('rating_data')->getRatingCode()));
        }
        return Mage::helper('rating')->__('New Rating');
    }
}
