<?php

namespace PhpKmsJwt;

use Aws\Kms\KmsClient;
use Aws\Sts\StsClient;

class AwsKms
{
    private $kms;

    /**
     * Initialize an AWS KMS connection.
     *
     * $credentials = [
     *     'profile'            => (string) AWS Profile.
     *     'region'             => (string) AWS Region.
     *     'access_key_id'      => (string) AWS Access key ID.
     *     'secret_access_key'  => (string) AWS Secret access key.
     *     'iam'                => (string) AWS IAM for assumuing a role via STS.
     *     'role'               => (string) AWS STS Role. Default: developer.
     * ]
     * @param  array $credentials Credentials for AWS KMS and STS authorization (See above).
     * @return void
     */
    public function __construct($credentials)
    {
        if (empty($credentials) || is_null($credentials)) {
            $credentials = array();
        }

        $credentials['profile'] = $credentials['profile'] ? $credentials['profile'] : getenv('AWS_PROFILE');
        $credentials['region'] = $credentials['region'] ? $credentials['region'] : getenv('AWS_REGION');
        $credentials['access_key_id'] = $credentials['access_key_id'] ? $credentials['access_key_id'] : getenv('AWS_ACCESS_KEY_ID');
        $credentials['secret_access_key'] = $credentials['secret_access_key'] ? $credentials['secret_access_key'] : getenv('AWS_SECRET_ACCESS_KEY');
        // iam and role are used for assuming an STS role
        $credentials['iam'] = $credentials['iam'] ? $credentials['iam'] : getenv('AWS_STS_IAM');
        $credentials['role'] = $credentials['role'] ? $credentials['role'] : getenv('AWS_STS_ROLE');

        $aws_credentials = array(
            'profile' => $credentials['profile'],
            'region'  => $credentials['region'],
        );

        // Try to assume credentials
        $assumedCredentials = $this->getSTSCredentials($credentials);
        if (!empty($assumedCredentials)) {
            $aws_credentials['credentials'] = $assumedCredentials;
        } else {
            $aws_credentials['key'] = $credentials['access_key_id'];
            $aws_credentials['secret'] = $credentials['secret_access_key'];
        }

        $this->kms = $this->initKMS($aws_credentials);
    }

    /**
     * Try to assume a role using AWS STS credentials.
     * @param  array $credentials AWS STS configuration options.
     * @return array              Credentials for AWS KMS authorization. (See AWS Documentation)
     */
    private function getSTSCredentials($credentials)
    {
        if (is_null($credentials['iam']) || is_null($credentials['role'])) {
            return null;
        }
        try {
            $sts = StsClient::factory(array_filter(array(
                'profile' => $credentials['profile'],
                'region' => $credentials['region'],
                'key' =>  $credentials['access_key_id'],
                'secret' => $credentials['secret_access_key'],
            )));

            $assumedRole = $sts->AssumeRole(array(
                'RoleArn' => 'arn:aws:iam::' . $credentials['iam'] . ':role/' . $credentials['role'],
                'RoleSessionName' => 'aws-kms-assume-role-' . time(),
            ));

            return array(
                'key'    => $assumedRole['Credentials']['AccessKeyId'],
                'secret' => $assumedRole['Credentials']['SecretAccessKey'],
                'token'  => $assumedRole['Credentials']['SessionToken'],
            );
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Initialize an AWS KMS instance using provided credentials.
     * @param  array $credentials AWS KMS configuration options. (See AWS documentation)
     * @return KmsClient
     */
    private function initKMS($credentials = null)
    {
        if (is_null($credentials)) {
            throw new \Exception("AwsKms::initKMS() - no credentials provided");
        }
        return KmsClient::factory(array_filter($credentials));
    }


    /**
     * Retrieve a data key from the AWS KMS using a master key ID.
     * @param  string $key_id AWS KMS master key ID.
     * @return array          List containing a dataKey in both plaintext and encrypted format.
     */
    public function getDataKey($key_id)
    {
        if (is_null($key_id)) {
            throw new \Exception("AwsKms::getDataKey() - no KMS master key id provided");
        }
        
        $dataKeyObject = $this->kms->generateDataKey(array(
            'KeyId' => $key_id,
            'KeySpec' => 'AES_256',
        ));

        if (!$dataKeyObject || empty($dataKeyObject['Plaintext']) || empty($dataKeyObject['CiphertextBlob'])) {
            throw new \Exception("AwsKms::getDataKey() - cannot generate a data key. Check your AWS credentials.");
        }

        return array(
            'dataKey' => $dataKeyObject['Plaintext'],
            'encryptedDataKey' => $dataKeyObject['CiphertextBlob']
        );
    }

    /**
     * Retrieve an AWS KMS client instance.
     * @return KmsClient
     */
    public function getClient()
    {
        return $this->kms;
    }
}
