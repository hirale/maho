<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Catalog_Block_Category_View extends Mage_Core_Block_Template
{
    /**
     * @return $this|Mage_Core_Block_Template
     * @throws Mage_Core_Model_Store_Exception
     */
    #[\Override]
    protected function _prepareLayout()
    {
        parent::_prepareLayout();

        $this->getLayout()->createBlock('catalog/breadcrumbs');

        $category = $this->getCurrentCategory();

        /** @var Mage_Page_Block_Html_Head $headBlock */
        $headBlock = $this->getLayout()->getBlock('head');
        if ($headBlock) {
            if ($title = $category->getMetaTitle()) {
                $headBlock->setTitle($title);
            }
            if ($description = $category->getMetaDescription()) {
                $headBlock->setDescription($description);
            }
            if ($keywords = $category->getMetaKeywords()) {
                $headBlock->setKeywords($keywords);
            }

            /** @var Mage_Catalog_Helper_Category $helper */
            $helper = $this->helper('catalog/category');
            if ($helper->canUseCanonicalTag()) {
                $headBlock->addLinkRel('canonical', $category->getUrl());
            }
            // Add rss feed in head block
            if ($this->isRssCatalogEnable() && $this->isTopCategory()) {
                $title = $this->helper('rss')->__('%s RSS Feed', $this->getCurrentCategory()->getName());
                $headBlock->addItem('rss', $this->getRssLink(), 'title="' . $title . '"');
            }
        }

        /** @var Mage_Page_Block_Html_Head */
        $titleBlock = $this->getLayout()->getBlock('title');
        if ($titleBlock) {
            $titleBlock->setTitle($this->helper('catalog/output')->categoryAttribute($category, $category->getName(), 'name'));

            // Add rss feed in title block
            if ($this->isRssCatalogEnable() && $this->isTopCategory()) {
                $titleBlock->getLinksBlock()->addLink(
                    $this->getIconSvg('rss'),
                    $this->getRssLink(),
                    $this->helper('rss')->__('Subscribe to RSS Feed'),
                );
            }
        }

        return $this;
    }

    /**
     * @return string
     */
    public function isRssCatalogEnable()
    {
        return Mage::getStoreConfig('rss/catalog/category');
    }

    /**
     * @return bool
     */
    public function isTopCategory()
    {
        return $this->getCurrentCategory()->getLevel() == 2;
    }

    /**
     * @return string
     * @throws Mage_Core_Model_Store_Exception
     */
    public function getRssLink()
    {
        return Mage::getUrl(
            'rss/catalog/category',
            [
                'cid' => $this->getCurrentCategory()->getId(),
                'store_id' => Mage::app()->getStore()->getId(),
            ],
        );
    }

    /**
     * @return string
     */
    public function getProductListHtml()
    {
        return $this->getChildHtml('product_list');
    }

    /**
     * Retrieve current category model object
     *
     * @return Mage_Catalog_Model_Category
     */
    public function getCurrentCategory()
    {
        if (!$this->hasData('current_category')) {
            $this->setData('current_category', Mage::registry('current_category'));
        }
        return $this->getData('current_category');
    }

    /**
     * @return string
     */
    public function getCmsBlockHtml()
    {
        if (!$this->getData('cms_block_html')) {
            $html = $this->getLayout()->createBlock('cms/block')
                ->setBlockId($this->getCurrentCategory()->getLandingPage())
                ->toHtml();
            $this->setData('cms_block_html', $html);
        }
        return $this->getData('cms_block_html');
    }

    /**
     * Check if category display mode is "Products Only"
     * @return bool
     */
    public function isProductMode()
    {
        return $this->getCurrentCategory()->getDisplayMode() == Mage_Catalog_Model_Category::DM_PRODUCT;
    }

    /**
     * Check if category display mode is "Static Block and Products"
     * @return bool
     */
    public function isMixedMode()
    {
        return $this->getCurrentCategory()->getDisplayMode() == Mage_Catalog_Model_Category::DM_MIXED;
    }

    /**
     * Check if category display mode is "Static Block Only"
     * For anchor category with applied filter Static Block Only mode not allowed
     *
     * @return bool
     */
    public function isContentMode()
    {
        $category = $this->getCurrentCategory();
        $res = false;
        if ($category->getDisplayMode() == Mage_Catalog_Model_Category::DM_PAGE) {
            $res = true;
            if ($category->getIsAnchor()) {
                $state = Mage::getSingleton('catalog/layer')->getState();
                if ($state && $state->getFilters()) {
                    $res = false;
                }
            }
        }
        return $res;
    }

    /**
     * Retrieve block cache tags based on category
     *
     * @return array
     */
    #[\Override]
    public function getCacheTags()
    {
        return array_merge(parent::getCacheTags(), $this->getCurrentCategory()->getCacheIdTags());
    }
}
