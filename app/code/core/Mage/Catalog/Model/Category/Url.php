<?php

/**
 * Maho
 *
 * @package    Mage_Catalog
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Catalog_Model_Category_Url
{
    /**
     * Url instance
     *
     * @var Mage_Core_Model_Url
     */
    protected $_url;

    /**
     * Factory instance
     *
     * @var Mage_Catalog_Model_Factory
     */
    protected $_factory;

    /**
     * Url rewrite instance
     *
     * @var Mage_Core_Model_Url_Rewrite
     */
    protected $_urlRewrite;

    /**
     * Initialize Url model
     */
    public function __construct(array $args = [])
    {
        $this->_factory = !empty($args['factory']) ? $args['factory'] : Mage::getSingleton('catalog/factory');
    }

    /**
     * Retrieve Url for specified category
     *
     * @return string
     */
    public function getCategoryUrl(Mage_Catalog_Model_Category $category)
    {
        $url = $category->getData('url');
        if ($url !== null) {
            return $url;
        }

        Varien_Profiler::start('REWRITE: ' . __METHOD__);

        if ($category->hasData('request_path') && $category->getData('request_path') != '') {
            $category->setData('url', $this->_getDirectUrl($category));
            Varien_Profiler::stop('REWRITE: ' . __METHOD__);
            return $category->getData('url');
        }

        $requestPath = $this->_getRequestPath($category);
        if ($requestPath) {
            $category->setRequestPath($requestPath);
            $category->setData('url', $this->_getDirectUrl($category));
            Varien_Profiler::stop('REWRITE: ' . __METHOD__);
            return $category->getData('url');
        }

        Varien_Profiler::stop('REWRITE: ' . __METHOD__);

        $category->setData('url', $category->getCategoryIdUrl());
        return $category->getData('url');
    }

    /**
     * Returns category URL by which it can be accessed
     * @return string
     */
    protected function _getDirectUrl(Mage_Catalog_Model_Category $category)
    {
        return $this->getUrlInstance()->getDirectUrl($category->getRequestPath());
    }

    /**
     * Retrieve request path
     *
     * @return bool|string
     */
    protected function _getRequestPath(Mage_Catalog_Model_Category $category)
    {
        $rewrite = $this->getUrlRewrite();
        $storeId = $category->getStoreId();
        if ($storeId) {
            $rewrite->setStoreId($storeId);
        }
        $idPath = 'category/' . $category->getId();
        $rewrite->loadByIdPath($idPath);
        if ($rewrite->getId()) {
            return $rewrite->getRequestPath();
        }
        return false;
    }

    /**
     * Retrieve Url instance
     *
     * @return Mage_Core_Model_Url
     */
    public function getUrlInstance()
    {
        if ($this->_url === null) {
            /** @var Mage_Core_Model_Url $model */
            $model = $this->_factory->getModel('core/url');
            $this->_url = $model;
        }
        return $this->_url;
    }

    /**
     * Retrieve Url rewrite instance
     *
     * @return Mage_Core_Model_Url_Rewrite
     */
    public function getUrlRewrite()
    {
        if ($this->_urlRewrite === null) {
            $this->_urlRewrite = $this->_factory->getUrlRewriteInstance();
        }
        return $this->_urlRewrite;
    }
}
