<?php

namespace Goszowski\QES;

interface Defines {

    const EM_RESULT_OK = 0;
    const EM_RESULT_ERROR = 1;
    const EM_RESULT_ERROR_WRONG_PARAMS = 2;
    const EM_RESULT_ERROR_INITIALIZED = 3;

    const EU_ERROR_NONE = 0x0000;
    const EU_ERROR_UNKNOWN = 0xFFFF;
    const EU_ERROR_NOT_SUPPORTED = 0xFFFE;

    const EU_ERROR_NOT_INITIALIZED = 0x0001;
    const EU_ERROR_BAD_PARAMETER = 0x0002;
    const EU_ERROR_LIBRARY_LOAD = 0x0003;
    const EU_ERROR_READ_SETTINGS = 0x0004;
    const EU_ERROR_TRANSMIT_REQUEST = 0x0005;
    const EU_ERROR_MEMORY_ALLOCATION = 0x0006;
    const EU_WARNING_END_OF_ENUM = 0x0007;
    const EU_ERROR_PROXY_NOT_AUTHORIZED = 0x0008;
    const EU_ERROR_NO_GUI_DIALOGS = 0x0009;
    const EU_ERROR_DOWNLOAD_FILE = 0x000A;
    const EU_ERROR_WRITE_SETTINGS = 0x000B;
    const EU_ERROR_CANCELED_BY_GUI = 0x000C;
    const EU_ERROR_OFFLINE_MODE = 0x000D;

    const EU_ERROR_KEY_MEDIAS_FAILED = 0x0011;
    const EU_ERROR_KEY_MEDIAS_ACCESS_FAILED = 0x0012;
    const EU_ERROR_KEY_MEDIAS_READ_FAILED = 0x0013;
    const EU_ERROR_KEY_MEDIAS_WRITE_FAILED = 0x0014;
    const EU_WARNING_KEY_MEDIAS_READ_ONLY = 0x0015;
    const EU_ERROR_KEY_MEDIAS_DELETE = 0x0016;
    const EU_ERROR_KEY_MEDIAS_CLEAR = 0x0017;
    const EU_ERROR_BAD_PRIVATE_KEY = 0x0018;

    const EU_ERROR_PKI_FORMATS_FAILED = 0x0021;
    const EU_ERROR_CSP_FAILED = 0x0022;
    const EU_ERROR_BAD_SIGNATURE = 0x0023;
    const EU_ERROR_AUTH_FAILED = 0x0024;
    const EU_ERROR_NOT_RECEIVER = 0x0025;

    const EU_ERROR_STORAGE_FAILED = 0x0031;
    const EU_ERROR_BAD_CERT = 0x0032;
    const EU_ERROR_CERT_NOT_FOUND = 0x0033;
    const EU_ERROR_INVALID_CERT_TIME = 0x0034;
    const EU_ERROR_CERT_IN_CRL = 0x0035;
    const EU_ERROR_BAD_CRL = 0x0036;
    const EU_ERROR_NO_VALID_CRLS = 0x0037;

    const EU_ERROR_GET_TIME_STAMP = 0x0041;
    const EU_ERROR_BAD_TSP_RESPONSE = 0x0042;
    const EU_ERROR_TSP_SERVER_CERT_NOT_FOUND = 0x0043;
    const EU_ERROR_TSP_SERVER_CERT_INVALID = 0x0044;

    const EU_ERROR_GET_OCSP_STATUS = 0x0051;
    const EU_ERROR_BAD_OCSP_RESPONSE = 0x0052;
    const EU_ERROR_CERT_BAD_BY_OCSP = 0x0053;
    const EU_ERROR_OCSP_SERVER_CERT_NOT_FOUND = 0x0054;
    const EU_ERROR_OCSP_SERVER_CERT_INVALID = 0x0055;

    const EU_ERROR_LDAP_ERROR = 0x0061;

    const EM_ENCODING_CP1251 = 1251;
    const EM_ENCODING_UTF8 = 65001;


    const EU_CERT_KEY_TYPE_UNKNOWN = 0x00;
    const EU_CERT_KEY_TYPE_DSTU4145 = 0x01;
    const EU_CERT_KEY_TYPE_RSA = 0x02;

    const EU_KEY_USAGE_UNKNOWN = 0x0000;
    const EU_KEY_USAGE_DIGITAL_SIGNATURE = 0x0001;
    const EU_KEY_USAGE_KEY_AGREEMENT = 0x0010;

    const EU_RECIPIENT_APPEND_TYPE_BY_ISSUER_SERIAL = 0x01;
    const EU_RECIPIENT_APPEND_TYPE_BY_KEY_ID = 0x02;

    const EU_SUBJECT_TYPE_UNDIFFERENCED = 0;
    const EU_SUBJECT_TYPE_CA = 1;
    const EU_SUBJECT_TYPE_CA_SERVER = 2;
    const EU_SUBJECT_TYPE_RA_ADMINISTRATOR = 3;
    const EU_SUBJECT_TYPE_END_USER = 4;

    const EU_SUBJECT_CA_SERVER_SUB_TYPE_UNDIFFERENCED = 0;
    const EU_SUBJECT_CA_SERVER_SUB_TYPE_CMP = 1;
    const EU_SUBJECT_CA_SERVER_SUB_TYPE_TSP = 2;
    const EU_SUBJECT_CA_SERVER_SUB_TYPE_OCSP = 3;

    const EU_CTX_HASH_ALGO_UNKNOWN = 0x00;
    const EU_CTX_HASH_ALGO_GOST34311 = 0x01;
    const EU_CTX_HASH_ALGO_SHA160 = 0x02;
    const EU_CTX_HASH_ALGO_SHA224 = 0x03;
    const EU_CTX_HASH_ALGO_SHA256 = 0x04;

    const EU_CTX_SIGN_UNKNOWN = 0x00;
    const EU_CTX_SIGN_DSTU4145_WITH_GOST34311 = 0x01;
    const EU_CTX_SIGN_RSA_WITH_SHA = 0x02;

    const EU_RESOLVE_OIDS_PARAMETER = "ResolveOIDs";
    const EU_SIGN_INCLUDE_CONTENT_TIME_STAMP_PARAMETER = "SignIncludeContentTimeStamp";
    const EU_SIGN_TYPE_PARAMETER = "SignType";
    const EU_SIGN_INCLUDE_CA_CERTIFICATES_PARAMETER = "SignIncludeCACertificates";

    const EU_SIGN_TYPE_UNKNOWN = 0x00;
    const EU_SIGN_TYPE_CADES_BES = 0x01;
    const EU_SIGN_TYPE_CADES_T = 0x04;
    const EU_SIGN_TYPE_CADES_C = 0x08;
    const EU_SIGN_TYPE_CADES_X_LONG = 0x10;

    const EU_OID_EXT_KEY_USAGE_STAMP = "1.2.804.2.1.1.1.3.9";
}
