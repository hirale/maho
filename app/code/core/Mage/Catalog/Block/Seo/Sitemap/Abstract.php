<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

abstract class Mage_Catalog_Block_Seo_Sitemap_Abstract extends Mage_Core_Block_Template
{
    /**
     * Init pager
     *
     * @param string $pagerName
     */
    public function bindPager($pagerName)
    {
        $pager = $this->getLayout()->getBlock($pagerName);
        /** @var Mage_Page_Block_Html_Pager $pager */
        if ($pager) {
            $pager->setAvailableLimit([50 => 50]);
            $pager->setCollection($this->getCollection());
            $pager->setShowPerPage(false);
        }
    }

    /**
     * Get item URL
     *
     * In most cases should be overridden in descendant blocks
     *
     * @param Mage_Catalog_Block_Seo_Sitemap_Abstract $item
     * @return string
     */
    public function getItemUrl($item)
    {
        return $item->getUrl();
    }
}
