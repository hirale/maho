<?php

/**
 * Maho
 *
 * @package    Mage_Dataflow
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2024 The OpenMage Contributors (https://openmage.org)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

class Mage_Dataflow_Model_Convert
{
    public static function convert($class, $method, $data, array $vars = [])
    {
        if (is_string($class)) {
            $class = new $class();
        }
        $action = new Mage_Dataflow_Model_Convert_Action();
        $action->setParam('method', $method)->setParam('class', $class);

        $container = $action->getContainer();
        $container->setData($data)->setVars($vars);

        $action->run();
        return $action->getData();
    }
}
