<?php

/**
 * Maho
 *
 * @package    Mage_Adminhtml
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Adminhtml_Block_Catalog_Product_Helper_Form_Gallery_Content extends Mage_Adminhtml_Block_Widget
{
    /**
     * Type of uploader block
     *
     * @var string
     */
    protected $_uploaderType = 'uploader/multiple';

    public function __construct()
    {
        parent::__construct();
        $this->setTemplate('catalog/product/helper/gallery.phtml');
    }

    #[\Override]
    protected function _prepareLayout()
    {
        $this->setChild(
            'uploader',
            $this->getLayout()->createBlock($this->_uploaderType),
        );

        $this->getUploader()->getUploaderConfig()
            ->setFileParameterName('image')
            ->setTarget(Mage::getModel('adminhtml/url')->addSessionParam()->getUrl(
                '*/catalog_product_gallery/upload',
                ['_query' => false],
            ));

        $browseConfig = $this->getUploader()->getButtonConfig();
        $browseConfig
            ->setAttributes([
                'accept' => $browseConfig->getMimeTypesByExtensions(Varien_Io_File::ALLOWED_IMAGES_EXTENSIONS),
            ]);

        Mage::dispatchEvent('catalog_product_gallery_prepare_layout', ['block' => $this]);

        return parent::_prepareLayout();
    }

    /**
     * Retrieve uploader block
     *
     * @return Mage_Uploader_Block_Multiple
     */
    public function getUploader()
    {
        return $this->getChild('uploader');
    }

    /**
     * Retrieve uploader block html
     *
     * @return string
     */
    public function getUploaderHtml()
    {
        return $this->getChildHtml('uploader');
    }

    /**
     * @return string
     */
    public function getJsObjectName()
    {
        return $this->getHtmlId() . 'JsObject';
    }

    /**
     * @return string
     */
    public function getAddImagesButton()
    {
        return $this->getButtonHtml(
            Mage::helper('catalog')->__('Add New Images'),
            $this->getJsObjectName() . '.showUploader()',
            'add',
            $this->getHtmlId() . '_add_images_button',
        );
    }

    /**
     * @return string
     */
    public function getImagesJson()
    {
        if (is_array($this->getElement()->getValue())) {
            $value = $this->getElement()->getValue();
            if (count($value['images']) > 0) {
                foreach ($value['images'] as &$image) {
                    $image['url'] = Mage::getSingleton('catalog/product_media_config')
                                        ->getMediaUrl($image['file']);
                }
                return Mage::helper('core')->jsonEncode($value['images']);
            }
        }
        return '[]';
    }

    /**
     * @return string
     */
    public function getImagesValuesJson()
    {
        $values = [];
        foreach ($this->getMediaAttributes() as $attribute) {
            /** @var Mage_Eav_Model_Entity_Attribute $attribute */
            $attributeCode = $attribute->getAttributeCode();
            $values[$attributeCode] = $this->getElement()->getDataObject()->getData($attributeCode);
        }
        return Mage::helper('core')->jsonEncode($values);
    }

    /**
     * @return array
     */
    public function getImageTypes()
    {
        $imageTypes = [];
        foreach ($this->getMediaAttributes() as $attribute) {
            /** @var Mage_Eav_Model_Entity_Attribute $attribute */
            $imageTypes[$attribute->getAttributeCode()] = [
                'label' => $attribute->getFrontend()->getLabel() . ' '
                         . Mage::helper('catalog')->__($this->getElement()->getScopeLabel($attribute)),
                'field' => $this->getElement()->getAttributeFieldName($attribute),
            ];
        }
        return $imageTypes;
    }

    /**
     * @return bool
     */
    public function hasUseDefault()
    {
        foreach ($this->getMediaAttributes() as $attribute) {
            if ($this->getElement()->canDisplayUseDefault($attribute)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array
     */
    public function getMediaAttributes()
    {
        return $this->getElement()->getDataObject()->getMediaAttributes();
    }

    /**
     * @return string
     */
    public function getImageTypesJson()
    {
        return Mage::helper('core')->jsonEncode($this->getImageTypes());
    }
}
