<?php

/**
 * Maho
 *
 * @package    Mage_Log
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2019-2024 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * @method Mage_Log_Model_Resource_Log _getResource()
 * @method Mage_Log_Model_Resource_Log getResource()
 * @method string getSessionId()
 * @method $this setSessionId(string $value)
 * @method string getFirstVisitAt()
 * @method $this setFirstVisitAt(string $value)
 * @method string getLastVisitAt()
 * @method $this setLastVisitAt(string $value)
 * @method int getLastUrlId()
 * @method $this setLastUrlId(int $value)
 * @method int getStoreId()
 * @method $this setStoreId(int $value)
 */
class Mage_Log_Model_Log extends Mage_Core_Model_Abstract
{
    public const XML_LOG_CLEAN_DAYS    = 'system/log/clean_after_day';

    /**
     * Init Resource Model
     *
     */
    #[\Override]
    protected function _construct()
    {
        $this->_init('log/log');
    }

    /**
     * @return int
     */
    public function getLogCleanTime()
    {
        return Mage::getStoreConfigAsInt(self::XML_LOG_CLEAN_DAYS) * 60 * 60 * 24;
    }

    /**
     * Clean Logs
     *
     * @return $this
     */
    public function clean()
    {
        $this->getResource()->clean($this);
        return $this;
    }
}
