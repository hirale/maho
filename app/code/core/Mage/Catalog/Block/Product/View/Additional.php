<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Catalog_Block_Product_View_Additional extends Mage_Core_Block_Template
{
    protected $_list;

    public function __construct()
    {
        parent::__construct();
        $this->setTemplate('catalog/product/view/additional.phtml');
    }

    /**
     * @return array
     */
    public function getChildHtmlList()
    {
        if (is_null($this->_list)) {
            $this->_list = [];
            foreach ($this->getSortedChildren() as $name) {
                $block = $this->getLayout()->getBlock($name);
                if (!$block) {
                    Mage::exception(Mage::helper('catalog')->__('Invalid block: %s.', $name));
                }
                $this->_list[] = $block->toHtml();
            }
        }
        return $this->_list;
    }
}
