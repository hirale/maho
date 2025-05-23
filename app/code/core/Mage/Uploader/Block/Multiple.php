<?php

/**
 * Maho
 *
 * @package    Mage_Uploader
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Uploader_Block_Multiple extends Mage_Uploader_Block_Abstract
{
    public const DEFAULT_UPLOAD_BUTTON_ID_SUFFIX = 'upload';

    /**
     * @return $this
     */
    #[\Override]
    protected function _prepareLayout()
    {
        parent::_prepareLayout();

        $this->setChild(
            'upload_button',
            $this->getLayout()->createBlock('adminhtml/widget_button')
                ->addData([
                    'id'      => $this->getElementId(self::DEFAULT_UPLOAD_BUTTON_ID_SUFFIX),
                    'label'   => Mage::helper('uploader')->__('Upload Files'),
                    'type'    => 'button',
                ]),
        );

        $this->_addElementIdsMapping([
            'upload' => $this->_prepareElementsIds([self::DEFAULT_UPLOAD_BUTTON_ID_SUFFIX]),
        ]);

        return $this;
    }

    /**
     * Get upload button html
     *
     * @return string
     */
    public function getUploadButtonHtml()
    {
        return $this->getChildHtml('upload_button');
    }
}
