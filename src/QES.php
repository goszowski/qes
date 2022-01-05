<?php

namespace Goszowski\QES;

abstract class QES implements Defines {

    protected KeysBag $keysBag;

    public function __construct($signKey, $encryptKey, $decryptKey, $decryptPassword)
    {
        euspe_setcharset(self::EM_ENCODING_UTF8);

        $this->result = self::EM_RESULT_ERROR;
        $this->errorCode = self::EU_ERROR_UNKNOWN;

        $this->keysBag = new KeysBag(
            $signKey,
            $encryptKey,
            $decryptKey,
            $decryptPassword,
        );
    }

    protected function getErrorMessageByCode($code) : string
    {
        $message = null;
        euspe_geterrdescr($code, $message);

        return $message;
    }

    protected function throwException(string $message, int $code)
    {
        throw new Exception("$message ($code): " . $this->getErrorMessageByCode($this->errorCode));
    }
}
