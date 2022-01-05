<?php

namespace Goszowski\QES;

class Signature extends QES {

    protected SignInfoBag $signInfo;

    public function __construct($signKey, $encryptKey, $decryptKey, $decryptPassword)
    {
        parent::__construct($signKey, $encryptKey, $decryptKey, $decryptPassword);

        $this->signInfo = new SignInfoBag;
    }

    public function apply($data) : array
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
        $this->result = euspe_ctxsigndata($this->pkContext, self::EU_CTX_HASH_ALGO_GOST34311, $data, false, true, $signature, $this->errorCode);
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

    public function verify($data, $signature)
    {

    }
}
