<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Catalog_Category_Tabs extends Mage_Adminhtml_Block_Widget_Tabs
{
    /**
     * Default Attribute Tab Block
     *
     * @var string
     */
    protected $_attributeTabBlock = 'adminhtml/catalog_category_tab_attributes';

    /**
     * Initialize Tabs
     *
     */
    public function __construct()
    {
        parent::__construct();
        $this->setId('category_info_tabs');
        $this->setDestElementId('category_tab_content');
        $this->setTitle(Mage::helper('catalog')->__('Category Data'));
        $this->setTemplate('widget/tabshoriz.phtml');
    }

    /**
     * Retrieve cattegory object
     *
     * @return Mage_Catalog_Model_Category
     */
    public function getCategory()
    {
        return Mage::registry('current_category');
    }

    /**
     * Return Adminhtml Catalog Helper
     *
     * @return Mage_Adminhtml_Helper_Catalog
     */
    public function getCatalogHelper()
    {
        return Mage::helper('adminhtml/catalog');
    }

    /**
     * Getting attribute block name for tabs
     *
     * @return string
     */
    public function getAttributeTabBlock()
    {
        if ($block = $this->getCatalogHelper()->getCategoryAttributeTabBlock()) {
            return $block;
        }
        return $this->_attributeTabBlock;
    }

    /**
     * Prepare Layout Content
     *
     * @return $this
     */
    #[\Override]
    protected function _prepareLayout()
    {
        $categoryAttributes = $this->getCategory()->getAttributes();
        if (!$this->getCategory()->getId()) {
            foreach ($categoryAttributes as $attribute) {
                $default = $attribute->getDefaultValue();
                if ($default != '') {
                    $this->getCategory()->setData($attribute->getAttributeCode(), $default);
                }
            }
        }

        $attributeSetId     = $this->getCategory()->getDefaultAttributeSetId();
        /** @var Mage_Eav_Model_Resource_Entity_Attribute_Group_Collection $groupCollection */
        $groupCollection    = Mage::getResourceModel('eav/entity_attribute_group_collection')
            ->setAttributeSetFilter($attributeSetId)
            ->setSortOrder()
            ->load();
        $defaultGroupId = 0;
        foreach ($groupCollection as $group) {
            /** @var Mage_Eav_Model_Entity_Attribute_Group $group */
            if ($defaultGroupId == 0 || $group->getIsDefault()) {
                $defaultGroupId = $group->getId();
            }
        }

        foreach ($groupCollection as $group) {
            /** @var Mage_Eav_Model_Entity_Attribute_Group $group */
            $attributes = [];
            foreach ($categoryAttributes as $attribute) {
                /** @var Mage_Eav_Model_Entity_Attribute $attribute */
                if ($attribute->isInGroup($attributeSetId, $group->getId())) {
                    $attributes[] = $attribute;
                }
            }

            // do not add grops without attributes
            if (!$attributes) {
                continue;
            }

            $active  = $defaultGroupId == $group->getId();
            $block = $this->getLayout()->createBlock($this->getAttributeTabBlock(), '')
                ->setGroup($group)
                ->setAttributes($attributes)
                ->setAddHiddenFields($active)
                ->toHtml();
            $this->addTab('group_' . $group->getId(), [
                'label'     => Mage::helper('catalog')->__($group->getAttributeGroupName()),
                'content'   => $block,
                'active'    => $active,
            ]);
        }

        $this->addTab('products', [
            'label'     => Mage::helper('catalog')->__('Category Products'),
            'content'   => $this->getLayout()->createBlock(
                'adminhtml/catalog_category_tab_product',
                'category.product.grid',
            )->toHtml(),
        ]);

        // dispatch event add custom tabs
        Mage::dispatchEvent('adminhtml_catalog_category_tabs', [
            'tabs'  => $this,
        ]);

        return parent::_prepareLayout();
    }
}
