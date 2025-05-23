<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_System_Convert_Profile_Edit_Tab_Run extends Mage_Adminhtml_Block_Template
{
    public function __construct()
    {
        parent::__construct();
        $this->setTemplate('system/convert/profile/run.phtml');
    }

    public function getRunButtonHtml()
    {
        $html = $this->getLayout()->createBlock('adminhtml/widget_button')->setType('button')
            ->setClass('save')->setLabel($this->__('Run Profile in Popup'))
            ->setOnClick('runProfile(true)')
            ->toHtml();

        return $html;
    }

    public function getProfileId()
    {
        return Mage::registry('current_convert_profile')->getId();
    }

    public function getImportedFiles()
    {
        $files = [];
        $path = Mage::app()->getConfig()->getTempVarDir() . '/import';
        if (!is_readable($path)) {
            return $files;
        }
        $dir = dir($path);
        while (($entry = $dir->read()) !== false) {
            if ($entry != '.'
                && $entry != '..'
                && strtolower(substr($entry, strrpos($entry, '.') + 1)) == $this->getParseType()
            ) {
                $files[] = $entry;
            }
        }
        sort($files);
        $dir->close();
        return $files;
    }

    public function getParseType()
    {
        $data = Mage::registry('current_convert_profile')->getGuiData();
        if ($data) {
            return ($data['parse']['type'] == 'excel_xml') ? 'xml' : $data['parse']['type'];
        }
    }
}
