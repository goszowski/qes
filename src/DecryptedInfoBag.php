<?php

namespace Goszowski\QES;

class DecryptedInfoBag {

    public $data = null;
    public $signTime = null;
    public $useTSP = false;
    public $issuer = '';
    public $issuerCN = '';
    public $serial = '';
    public $subject = '';
    public $subjCN = '';
    public $subjOrg = '';
    public $subjOrgUnit = '';
    public $subjTitle = '';
    public $subjState = '';
    public $subjLocality = '';
    public $subjFullName = '';
    public $subjAddress = '';
    public $subjPhone = '';
    public $subjEMail = '';
    public $subjDNS = '';
    public $subjEDRPOUCode = '';
    public $subjDRFOCode = '';
}
