<?php

/**
 * Maho
 *
 * @package    Mage_Rss
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Rss_Block_Catalog_Review extends Mage_Rss_Block_Abstract
{
    /**
     * Cache tag constant for feed reviews
     *
     * @var string
     */
    public const CACHE_TAG = 'block_html_rss_catalog_review';

    /**
     * Initialize cache
     */
    #[\Override]
    protected function _construct()
    {
        $this->setCacheTags([self::CACHE_TAG]);
        /*
        * setting cache to save the rss for 10 minutes
        */
        $this->setCacheKey('rss_catalog_review');
        $this->setCacheLifetime(600);
    }

    /**
     * Render XML response
     *
     * @return string
     */
    #[\Override]
    protected function _toHtml()
    {
        $newUrl = Mage::getUrl('rss/catalog/review');
        $title = Mage::helper('rss')->__('Pending product review(s)');
        Mage::helper('rss')->disableFlat();

        $rssObj = Mage::getModel('rss/rss');
        $data = [
            'title' => $title,
            'description' => $title,
            'link'        => $newUrl,
            'charset'     => 'UTF-8',
        ];
        $rssObj->_addHeader($data);

        $reviewModel = Mage::getModel('review/review');

        $collection = $reviewModel->getProductCollection()
            ->addStatusFilter($reviewModel->getPendingStatus())
            ->addAttributeToSelect('name', 'inner')
            ->setDateOrder();

        Mage::dispatchEvent('rss_catalog_review_collection_select', ['collection' => $collection]);

        Mage::getSingleton('core/resource_iterator')->walk(
            $collection->getSelect(),
            [[$this, 'addReviewItemXmlCallback']],
            ['rssObj' => $rssObj, 'reviewModel' => $reviewModel],
        );
        return $rssObj->createRssXml();
    }

    /**
     * Format single RSS element
     *
     * @param array $args
     */
    public function addReviewItemXmlCallback($args)
    {
        $rssObj = $args['rssObj'];
        $row = $args['row'];

        $store = Mage::app()->getStore($row['store_id']);
        $urlModel = Mage::getModel('core/url')->setStore($store);
        $productUrl = $urlModel->getUrl('catalog/product/view', ['id' => $row['entity_id']]);
        $reviewUrl = Mage::helper('adminhtml')->getUrl(
            'adminhtml/catalog_product_review/edit/',
            ['id' => $row['review_id'], '_secure' => true, '_nosecret' => true],
        );
        $storeName = $store->getName();

        $description = '<p>'
                     . $this->__('Product: <a href="%s">%s</a> <br/>', $productUrl, $row['name'])
                     . $this->__('Summary of review: %s <br/>', $row['title'])
                     . $this->__('Review: %s <br/>', $row['detail'])
                     . $this->__('Store: %s <br/>', $storeName)
                     . $this->__('click <a href="%s">here</a> to view the review', $reviewUrl)
                     . '</p>';
        $data = [
            'title'         => $this->__('Product: "%s" review By: %s', $row['name'], $row['nickname']),
            'link'          => 'test',
            'description'   => $description,
        ];
        $rssObj->_addEntry($data);
    }
}
