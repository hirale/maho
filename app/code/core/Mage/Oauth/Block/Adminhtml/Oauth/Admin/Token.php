<?php

/**
 * Maho
 *
 * @package    Mage_Oauth
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Oauth_Block_Adminhtml_Oauth_Admin_Token extends Mage_Adminhtml_Block_Widget_Grid_Container
{
    /**
     * Construct grid container
     */
    public function __construct()
    {
        parent::__construct();

        $this->_blockGroup = 'oauth';
        $this->_controller = 'adminhtml_oauth_admin_token';
        $this->_headerText = Mage::helper('adminhtml')->__('My Applications');
        $this->_removeButton('add');
    }
}
