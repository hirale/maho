<?php

/**
 * Maho
 *
 * @package    Mage_Usa
 * @copyright  Copyright (c) 2006-2020 Magento, Inc. (https://magento.com)
 * @copyright  Copyright (c) 2022-2023 The OpenMage Contributors (https://openmage.org)
 * @copyright  Copyright (c) 2024 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

/**
 * DHL International (API v1.4) Label Creation
 *
 * @deprecated now the process of creating the label is on DHL side
 */
class Mage_Usa_Model_Shipping_Carrier_Dhl_Label_Pdf
{
    /**
     * Label Information
     *
     * @var SimpleXMLElement
     */
    protected $_info;

    /**
     * Shipment Request
     *
     * @var Mage_Shipping_Model_Shipment_Request
     */
    protected $_request;

    /**
     * Dhl International Label Creation Class constructor
     */
    public function __construct(array $arguments)
    {
        $this->_info    = $arguments['info'];
        $this->_request = $arguments['request'];
    }

    /**
     * Create Label
     *
     * @return string
     */
    public function render()
    {
        $pdf = new Zend_Pdf();

        $pdfBuilder = new Mage_Usa_Model_Shipping_Carrier_Dhl_Label_Pdf_PageBuilder();

        $template = new Mage_Usa_Model_Shipping_Carrier_Dhl_Label_Pdf_Page(Zend_Pdf_Page::SIZE_A4_LANDSCAPE);
        $pdfBuilder->setPage($template)
            ->addProductName((string) $this->_info->ProductShortName)
            ->addProductContentCode((string) $this->_info->ProductContentCode)
        //->addUnitId({unitId})
        //->addReferenceData({referenceData})
            ->addSenderInfo($this->_info->Shipper)
            ->addOriginInfo((string) $this->_info->OriginServiceArea->ServiceAreaCode)
            ->addReceiveInfo($this->_info->Consignee)
            ->addDestinationFacilityCode(
                (string) $this->_info->Consignee->CountryCode,
                (string) $this->_info->DestinationServiceArea->ServiceAreaCode,
                (string) $this->_info->DestinationServiceArea->FacilityCode,
            )
            ->addServiceFeaturesCodes()
            ->addDeliveryDateCode()
            ->addShipmentInformation($this->_request->getOrderShipment())
            ->addDateInfo($this->_info->ShipmentDate)
            ->addWeightInfo((string) $this->_info->ChargeableWeight, (string) $this->_info->WeightUnit)
            ->addWaybillBarcode((string) $this->_info->AirwayBillNumber, (string) $this->_info->Barcodes->AWBBarCode)
            ->addRoutingBarcode(
                (string) $this->_info->DHLRoutingCode,
                (string) $this->_info->DHLRoutingDataId,
                (string) $this->_info->Barcodes->DHLRoutingBarCode,
            )
            ->addBorder();

        $packages = array_values($this->_request->getPackages());
        $i = 0;
        foreach ($this->_info->Pieces->Piece as $piece) {
            $page = new Mage_Usa_Model_Shipping_Carrier_Dhl_Label_Pdf_Page($template);
            $pdfBuilder->setPage($page)
                ->addPieceNumber((int) $piece->PieceNumber, (int) $this->_info->Piece)
                ->addContentInfo($packages[$i])
                ->addPieceIdBarcode(
                    (string) $piece->DataIdentifier,
                    (string) $piece->LicensePlate,
                    (string) $piece->LicensePlateBarCode,
                );
            $pdf->pages[] = $page;
            $i++;
        }
        return $pdf->render();
    }
}
