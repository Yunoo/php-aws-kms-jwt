<?php

namespace App;

class Keymaker
{
    private $cipher_algo;
    private $hash_algo;
    private $iv_num_bytes;
    private $kms;
    private $key_id;
    
    /**
     * Keymaker. Generates signed tokens.
     *
     * @param  AwsKms $kms    AwsKms class instance.
     * @param  string $key_id AWS KMS master key ID.
     * @param  string $iss    JWT token issuer.
     * @return void
     */
    public function __construct($kms, $key_id, $iss, $cipher_algo = 'aes-256-gcm', $hash_algo = 'sha256')
    {
        if (is_null($kms)) {
            throw new \Exception("Keymaker:: - no KMS instance provided");
        }

        if (is_null($key_id)) {
            throw new \Exception("Keymaker:: - no KMS master key ID provided");
        }

        if (!in_array($cipher_algo, openssl_get_cipher_methods(true))) {
            throw new \Exception("Keymaker:: - unknown cipher algo {$this->cipher_algo}");
        }

        if (!in_array($hash_algo, openssl_get_md_methods(true))) {
            throw new \Exception("Keymaker:: - unknown hash algo {$this->hash_algo}");
        }

        $this->kms = $kms;
        $this->key_id = $key_id;
        $this->iss = $iss;
        $this->cipher_algo = $cipher_algo;
        $this->hash_algo = $hash_algo;
        $this->iv_num_bytes = openssl_cipher_iv_length($cipher_algo);
    }

    /**
     * Check timestamp format.
     *
     * @param  string|int $timestamp Unix timestamp.
     * @return boolean
     */
    private function checkTimestamp($timestamp)
    {
        return is_numeric($timestamp) && (int) $timestamp == $timestamp;
    }

    /**
     * Generate a KMS signed JWT token.
     * JWT RFC: https://tools.ietf.org/html/rfc7519
     *
     * @param  string       $aud  Token target audience (e.g. entitlement)
     * @param  int          $exp  Token Expiration Time claim (timestamp).
     * @param  int          $exp  Token Not Before claim (timestamp).
     * @param  array|string $data Arbitary payload data.
     * @return string             The encrypted string in binary format.
     */
    public function generateSignedJWT($aud, $exp, $nbf, $data)
    {
        $key_id = $this->key_id;
        $dataKeyArray = $this->kms->getDataKey($key_id);

        $headers = array(
            "typ" => "JWT",
            "alg" => "KMS256",
            "kid" => $key_id,
        );

        $iat = time();
        $exp_timestamp = ($this->checkTimestamp($exp) && (int) $exp > $iat) ? (int) $exp : null;
        $nbf_timestamp = ($this->checkTimestamp($nbf) && (int) $nbf > $iat && (int) $nbf < $exp_timestamp) ? $nbf : null;
      
        $payload = array_filter(array(
            "iss" => $this->iss,
            "aud" => $aud,
            'exp' => $exp_timestamp,
            'nbf' => $nbf_timestamp,
            'iat' => time(),
            "edk" => base64_encode($dataKeyArray['encryptedDataKey']),
        ));

        if (!empty($data)) {
            $payload['data'] = $data;
        }
      
        $plaintext = $this->base64url_encode(json_encode($headers)) . '.' . $this->base64url_encode(json_encode($payload));
        $signature = $this->base64url_encode($this->encrypt($plaintext, $dataKeyArray['dataKey']));
        $token = $plaintext . '.' . $signature;
        return $token;
    }

    /**
     * Encrypt a string using
     *
     * @param  string $msg String to encrypt.
     * @param  string $key Encryption key.
     * @return string      The encrypted string in binary format.
     */
    public function encrypt($msg, $key)
    {
        $iv = openssl_random_pseudo_bytes($this->iv_num_bytes);
        $keyhash = openssl_digest($key, $this->hash_algo, true);

        $opts =  OPENSSL_RAW_DATA;
        $encrypted = openssl_encrypt($msg, $this->cipher_algo, $keyhash, $opts, $iv);

        if ($encrypted === false) {
            throw new \Exception('Keymaker::encrypt() - Encryption failed: ' . openssl_error_string());
        }

        return $iv . $encrypted;
    }

    /**
     * Create an url safe base64 representation.
     *
     * @param  string $data String to convert.
     * @return string       Base64 encoded url safe string.
     */
    private function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
