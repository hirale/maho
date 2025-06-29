<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024-2025 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Catalog url rewrites index model.
 * Responsibility for system actions:
 *  - Product save (changed assigned categories list, assigned websites or url key)
 *  - Category save (changed assigned products list, category move, changed url key)
 *  - Store save (new store creation, changed store group) - require reindex all data
 *  - Store group save (changed root category or group website) - require reindex all data
 *  - Seo config settings change - require reindex all data
 *
 * @package    Mage_Catalog
 */
class Mage_Catalog_Model_Indexer_Url extends Mage_Index_Model_Indexer_Abstract
{
    /**
     * Data key for matching result to be saved in
     */
    public const EVENT_MATCH_RESULT_KEY = 'catalog_url_match_result';

    /**
     * Index math: product save, category save, store save
     * store group save, config save
     *
     * @var array
     */
    protected $_matchedEntities = [
        Mage_Catalog_Model_Product::ENTITY => [
            Mage_Index_Model_Event::TYPE_SAVE,
        ],
        Mage_Catalog_Model_Category::ENTITY => [
            Mage_Index_Model_Event::TYPE_SAVE,
        ],
        Mage_Core_Model_Store::ENTITY => [
            Mage_Index_Model_Event::TYPE_SAVE,
        ],
        Mage_Core_Model_Store_Group::ENTITY => [
            Mage_Index_Model_Event::TYPE_SAVE,
        ],
        Mage_Core_Model_Config_Data::ENTITY => [
            Mage_Index_Model_Event::TYPE_SAVE,
        ],
        Mage_Catalog_Model_Convert_Adapter_Product::ENTITY => [
            Mage_Index_Model_Event::TYPE_SAVE,
        ],
    ];

    protected $_relatedConfigSettings = [
        Mage_Catalog_Helper_Category::XML_PATH_CATEGORY_URL_SUFFIX,
        Mage_Catalog_Helper_Product::XML_PATH_PRODUCT_URL_SUFFIX,
        Mage_Catalog_Helper_Product::XML_PATH_PRODUCT_URL_USE_CATEGORY,
    ];

    /**
     * Get Indexer name
     *
     * @return string
     */
    #[\Override]
    public function getName()
    {
        return Mage::helper('catalog')->__('Catalog URL Rewrites');
    }

    /**
     * Get Indexer description
     *
     * @return string
     */
    #[\Override]
    public function getDescription()
    {
        return Mage::helper('catalog')->__('Index product and categories URL rewrites');
    }

    /**
     * Check if event can be matched by process.
     * Overwrote for specific config save, store and store groups save matching
     *
     * @return bool
     */
    #[\Override]
    public function matchEvent(Mage_Index_Model_Event $event)
    {
        $data       = $event->getNewData();
        if (isset($data[self::EVENT_MATCH_RESULT_KEY])) {
            return $data[self::EVENT_MATCH_RESULT_KEY];
        }

        $entity = $event->getEntity();
        if ($entity == Mage_Core_Model_Store::ENTITY) {
            $store = $event->getDataObject();
            if ($store && ($store->isObjectNew() || $store->dataHasChangedFor('group_id'))) {
                $result = true;
            } else {
                $result = false;
            }
        } elseif ($entity == Mage_Core_Model_Store_Group::ENTITY) {
            $storeGroup = $event->getDataObject();
            $hasDataChanges = $storeGroup && ($storeGroup->dataHasChangedFor('root_category_id')
                || $storeGroup->dataHasChangedFor('website_id'));
            if ($storeGroup && !$storeGroup->isObjectNew() && $hasDataChanges) {
                $result = true;
            } else {
                $result = false;
            }
        } elseif ($entity == Mage_Core_Model_Config_Data::ENTITY) {
            $configData = $event->getDataObject();
            if ($configData && in_array($configData->getPath(), $this->_relatedConfigSettings)) {
                $result = $configData->isValueChanged();
            } else {
                $result = false;
            }
        } else {
            $result = parent::matchEvent($event);
        }

        $event->addNewData(self::EVENT_MATCH_RESULT_KEY, $result);

        return $result;
    }

    /**
     * Register data required by process in event object
     *
     * @return Mage_Catalog_Model_Indexer_Url
     */
    #[\Override]
    protected function _registerEvent(Mage_Index_Model_Event $event)
    {
        $event->addNewData(self::EVENT_MATCH_RESULT_KEY, true);
        $entity = $event->getEntity();
        switch ($entity) {
            case Mage_Catalog_Model_Product::ENTITY:
                $this->_registerProductEvent($event);
                break;

            case Mage_Catalog_Model_Category::ENTITY:
                $this->_registerCategoryEvent($event);
                break;

            case Mage_Catalog_Model_Convert_Adapter_Product::ENTITY:
                $event->addNewData('catalog_url_reindex_all', true);
                break;

            case Mage_Core_Model_Store::ENTITY:
            case Mage_Core_Model_Store_Group::ENTITY:
            case Mage_Core_Model_Config_Data::ENTITY:
                $process = $event->getProcess();
                $process->changeStatus(Mage_Index_Model_Process::STATUS_REQUIRE_REINDEX);
                break;
        }
        return $this;
    }

    /**
     * Register event data during product save process
     */
    protected function _registerProductEvent(Mage_Index_Model_Event $event)
    {
        $product = $event->getDataObject();
        $dataChange = $product->dataHasChangedFor('url_key')
            || $product->getIsChangedCategories()
            || $product->getIsChangedWebsites();

        if (!$product->getExcludeUrlRewrite() && $dataChange) {
            $event->addNewData('rewrite_product_ids', [$product->getId()]);
        }
    }

    /**
     * Register event data during category save process
     */
    protected function _registerCategoryEvent(Mage_Index_Model_Event $event)
    {
        $category = $event->getDataObject();
        if (!$category->getInitialSetupFlag() && $category->getLevel() > 1) {
            if ($category->dataHasChangedFor('url_key') || $category->getIsChangedProductList()) {
                $event->addNewData('rewrite_category_ids', [$category->getId()]);
            }
            /**
             * Check if category has another affected category ids (category move result)
             */
            if ($category->getAffectedCategoryIds()) {
                $event->addNewData('rewrite_category_ids', $category->getAffectedCategoryIds());
            }
        }
    }

    /**
     * Process event
     */
    #[\Override]
    protected function _processEvent(Mage_Index_Model_Event $event)
    {
        $data = $event->getNewData();
        if (!empty($data['catalog_url_reindex_all'])) {
            $this->reindexAll();
        }

        /** @var Mage_Catalog_Model_Url $urlModel */
        $urlModel = Mage::getSingleton('catalog/url');

        // Force rewrites history saving
        $dataObject = $event->getDataObject();
        if ($dataObject instanceof Varien_Object && $dataObject->hasData('save_rewrites_history')) {
            $urlModel->setShouldSaveRewritesHistory($dataObject->getData('save_rewrites_history'));
        }

        if (isset($data['rewrite_product_ids'])) {
            $urlModel->clearStoreInvalidRewrites(); // Maybe some products were moved or removed from website
            foreach (array_unique($data['rewrite_product_ids']) as $productId) {
                $urlModel->refreshProductRewrite($productId);
            }
        }

        if (isset($data['rewrite_category_ids'])) {
            $urlModel->clearStoreInvalidRewrites(); // Maybe some categories were moved
            foreach (array_unique($data['rewrite_category_ids']) as $categoryId) {
                $urlModel->refreshCategoryRewrite($categoryId);
            }
        }
    }

    /**
     * Rebuild all index data
     */
    #[\Override]
    public function reindexAll()
    {
        /** @var Mage_Catalog_Model_Resource_Url $resourceModel */
        $resourceModel = Mage::getResourceSingleton('catalog/url');
        $resourceModel->beginTransaction();
        try {
            Mage::getSingleton('catalog/url')->refreshRewrites();
            $resourceModel->commit();
        } catch (Exception $e) {
            $resourceModel->rollBack();
            throw $e;
        }
    }

    #[\Override]
    public function reindexEntity(int|array $entityIds): self
    {
        if (!is_array($entityIds)) {
            $entityIds = [$entityIds];
        }

        /** @var Mage_Catalog_Model_Url $urlModel */
        $urlModel = Mage::getSingleton('catalog/url');

        $urlModel->clearStoreInvalidRewrites();
        foreach ($entityIds as $productId) {
            $urlModel->refreshProductRewrite($productId);
        }

        return $this;
    }
}
