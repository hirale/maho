<?php

declare(strict_types=1);

/**
 * Maho
 *
 * @package    Mage_Directory
 * @copyright  Copyright (c) 2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Directory_Block_Adminhtml_Country_Edit_Tab_Translations extends Mage_Adminhtml_Block_Text_List implements Mage_Adminhtml_Block_Widget_Tab_Interface
{
    #[\Override]
    public function getTabLabel(): string
    {
        return Mage::helper('directory')->__('Manage Translations');
    }

    #[\Override]
    public function getTabTitle(): string
    {
        return Mage::helper('directory')->__('Manage Translations');
    }

    #[\Override]
    public function canShowTab(): bool
    {
        return $this->_isEditing();
    }

    #[\Override]
    public function isHidden(): bool
    {
        return !$this->_isEditing();
    }

    protected function _isEditing(): bool
    {
        $country = Mage::registry('current_country');
        return !is_null($country->getOrigData('country_id'));
    }
}
