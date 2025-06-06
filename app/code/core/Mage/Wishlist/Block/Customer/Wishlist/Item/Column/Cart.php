<?php

/**
 * Maho
 *
 * @package    Mage_Wishlist
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2021-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Wishlist_Block_Customer_Wishlist_Item_Column_Cart extends Mage_Wishlist_Block_Customer_Wishlist_Item_Column
{
    /**
     * Returns qty to show visually to user
     *
     * @return float
     */
    public function getAddToCartQty(Mage_Wishlist_Model_Item $item)
    {
        $qty = $item->getQty();
        return $qty ?: 1;
    }

    /**
     * Retrieve column related javascript code
     *
     * @return string
     */
    #[\Override]
    public function getJs()
    {
        $js = "
            function addWItemToCart(itemId) {
                addWItemToCartCustom(itemId, true)
            }

            function addWItemToCartCustom(itemId, sendGet) {
                var url = '';
                if (sendGet) {
                    url = '" . $this->getItemAddToCartUrl('%item%') . "';
                } else {
                    url = '" . $this->getItemAddToCartUrlCustom('%item%', false) . "';
                }
                url = url.replace('%item%', itemId);

                var form = document.getElementById('wishlist-view-form');
                if (form) {
                    var input = form['qty[' + itemId + ']'];
                    if (input) {
                        var separator = (url.indexOf('?') >= 0) ? '&' : '?';
                        url += separator + input.name + '=' + encodeURIComponent(input.value);
                    }
                }
                if (sendGet) {
                    window.location.href = encodeURI(url);
                } else {
                    customFormSubmit(url, '" . json_encode(['form_key' => $this->getFormKey()]) . "', 'post');
                }
            }
        ";

        $js .= parent::getJs();
        return $js;
    }
}
