<?php

/**
 * Maho
 *
 * @package    Mage_Page
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2020-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * Top menu block item renderer
 *
 * @method Varien_Data_Tree_Node getMenuTree()
 * @method string getChildrenWrapClass()
 */
class Mage_Page_Block_Html_Topmenu_Renderer extends Mage_Page_Block_Html_Topmenu
{
    protected $_templateFile;

    /**
     * Renders block html
     * @return string
     * @throws Exception
     */
    #[\Override]
    protected function _toHtml()
    {
        $this->_addCacheTags();
        $menuTree = $this->getMenuTree();
        $childrenWrapClass = $this->getChildrenWrapClass();
        if (!$this->getTemplate() || is_null($menuTree) || is_null($childrenWrapClass)) {
            throw new Exception("Top-menu renderer isn't fully configured.");
        }

        $includeFilePath = $this->getTemplateFile();
        if (!str_contains($this->getTemplateFile(), '..')) {
            $this->_templateFile = $includeFilePath;
        } else {
            throw new Exception('Not valid template file:' . $this->_templateFile);
        }
        return $this->render($menuTree, $childrenWrapClass);
    }

    /**
     * Add cache tags
     */
    protected function _addCacheTags()
    {
        $parentBlock = $this->getParentBlock();
        if ($parentBlock) {
            $this->addCacheTag($parentBlock->getCacheTags());
        }
    }

    /**
     * Fetches template. If template has return statement, than its value is used and direct output otherwise.
     * @param string $childrenWrapClass
     * @return string
     */
    public function render(Varien_Data_Tree_Node $menuTree, $childrenWrapClass)
    {
        ob_start();
        $html = include $this->_templateFile;
        $directOutput = ob_get_clean();

        if (is_string($html)) {
            return $html;
        } else {
            return $directOutput;
        }
    }
}
