<?php

namespace Goszowski\QES;

class KeysBag {

    public function __construct(
        protected $signKey, // Відкритий ключ для підписання
        protected $encryptKey, // Відкритий ключ для шифрування
        protected $decryptKey, // Закритий ключ
        protected $decryptPassword, // Пароль закритого ключа
    ) {}

    public function getSignKey()
    {
        return $this->signKey;
    }

    public function getEncryptKey()
    {
        return $this->encryptKey;
    }

    public function getDecryptKey()
    {
        return $this->decryptKey;
    }

    public function getDecryptPassword()
    {
        return $this->decryptPassword;
    }
}
