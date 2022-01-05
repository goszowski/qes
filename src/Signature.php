<?php

namespace Goszowski\QES;

class Signature extends QES {

    protected SignInfoBag $signInfo;

    public function __construct($signKey, $encryptKey, $decryptKey, $decryptPassword)
    {
        parent::__construct($signKey, $encryptKey, $decryptKey, $decryptPassword);

        $this->signInfo = new SignInfoBag;
    }

    public function create($data) : array
    {
        //Ініціалізація криптографічної бібліотеки
        $this->result = euspe_init($this->errorCode);
        if($this->result != self::EM_RESULT_OK)
        {
            $this->throwException('Виникла помилка при ініціалізації криптографічної бібліотеки', $this->errorCode);
        }

        // Створення контексту
        $this->result = euspe_ctxcreate($this->context, $this->errorCode);
        if($this->result != self::EM_RESULT_OK)
        {
            $this->throwException('Виникла помилка при створенні контексту', $this->errorCode);
        }

        // Зчитування ос. ключа
        $this->result = euspe_ctxreadprivatekeybinary(
            $this->context,
            $this->keysBag->getDecryptKey(),
            $this->keysBag->getDecryptPassword(),
            $this->pkContext,
            $this->errorCode,
        );
        if($this->result != self::EM_RESULT_OK)
        {
            // Очищення контексту
            euspe_ctxfree($this->context);
            $this->throwException('Виникла помилка при зчитуванні ос. ключа', $this->errorCode);
        }

        // Підписання даних
        $signature = '';
        $this->result = euspe_ctxsigndata($this->pkContext, self::EU_CTX_HASH_ALGO_GOST34311, $data, true, true, $signature, $this->errorCode);
        if($this->result != self::EM_RESULT_OK)
        {
            $this->throwException('Виникла помилка при підписанні даних', $this->errorCode);
        }

        // Перевірка підписаних даних
        $this->result = $this->verify($data, $signature);
        if($this->result != self::EM_RESULT_OK)
        {
            euspe_ctxfreeprivatekey($this->pkContext);
            euspe_ctxfree($this->context);
            $this->throwException('Виникла помилка при перевірці підписаних даних', $this->errorCode);
        }

        return [
            'signature' => $signature,
            'info' => $this->signInfo,
        ];
    }

    protected function verify($data, $signature)
    {
        return euspe_signverifyext(
            $data,
            $signature,
            $this->signInfo->signTime,
            $this->signInfo->useTSP,
            $this->signInfo->issuer,
            $this->signInfo->issuerCN,
            $this->signInfo->serial,
            $this->signInfo->subject,
            $this->signInfo->subjCN,
            $this->signInfo->subjOrg,
            $this->signInfo->subjOrgUnit,
            $this->signInfo->subjTitle,
            $this->signInfo->subjState,
            $this->signInfo->subjLocality,
            $this->signInfo->subjFullName,
            $this->signInfo->subjAddress,
            $this->signInfo->subjPhone,
            $this->signInfo->subjEMail,
            $this->signInfo->subjDNS,
            $this->signInfo->subjEDRPOUCode,
            $this->signInfo->subjDRFOCode,
            $this->errorCode,
        );
    }

    public function getSignatureInfo($data, $signature)
    {
        //Ініціалізація криптографічної бібліотеки
        $this->result = euspe_init($this->errorCode);
        if($this->result != self::EM_RESULT_OK)
        {
            $this->throwException('Виникла помилка при ініціалізації криптографічної бібліотеки', $this->errorCode);
        }

        // Створення контексту
        $this->result = euspe_ctxcreate($this->context, $this->errorCode);
        if($this->result != self::EM_RESULT_OK)
        {
            $this->throwException('Виникла помилка при створенні контексту', $this->errorCode);
        }

        // Зчитування ос. ключа
        $this->result = euspe_ctxreadprivatekeybinary(
            $this->context,
            $this->keysBag->getDecryptKey(),
            $this->keysBag->getDecryptPassword(),
            $this->pkContext,
            $this->errorCode,
        );
        if($this->result != self::EM_RESULT_OK)
        {
            // Очищення контексту
            euspe_ctxfree($this->context);
            $this->throwException('Виникла помилка при зчитуванні ос. ключа', $this->errorCode);
        }
        
        $this->result = $this->verify($data, $signature);
        if($this->result != self::EM_RESULT_OK)
        {
            euspe_ctxfreeprivatekey($this->pkContext);
            euspe_ctxfree($this->context);
            $this->throwException('Виникла помилка при перевірці підписаних даних', $this->errorCode);
        }

        return $this->signInfo;
    }


}
