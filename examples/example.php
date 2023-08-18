
<?php

require __DIR__ .'/../vendor/autoload.php';

use PhpKmsJwt\Keymaker;
use PhpKmsJwt\AwsKms;

// KMS master key. Use you own ID
// https://nsmith.net/aws-kms-cli
// Suggestion: Create and use an alias instead of an UUID
$key_id = 'a66f59f3-06cd-4bd8-badb-47435990a3f7';

try {
    /* Credentials object
     * Keys: 'profile', 'region', 'access_key_id', 'secret_access_key', 'iam', 'role'
     * It is possible to set the credentials using environment variables:
     * 'AWS_PROFILE', 'AWS_REGION', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_STS_IAM', 'AWS_STS_ROLE'
     */
    $credentials = array(
      'region' => 'eu-central-1',
      'version' => '2014-11-01',
      'iam' => '623377067247',
      'role' => 'developer',
    );
    $kms = new AwsKms($credentials);
    $keymaker = new Keymaker($kms, $key_id, 'ODP', 'aes-256-cbc');
    $exp = time() + 10*60;
    // Generate an AWS KMS singned JWT token
    $token = $keymaker->generateSignedJWT('entitlement', $exp, null, null);

    print_r($token . PHP_EOL);
} catch (\Exception $e) {
    echo 'Error: Cannot generate a JWT token';
    throw $e;
}

/*
 * Now you can send a request with the token to your other service
 *
 * // Guzzle 3.9 (deprecated)
 * use Guzzle\Http\Client;
 *
 * $url = 'https://httpbin.org';
 * $client = new Client($url);
 *
 * // Prepare payload
 * $payload = array('data' => 'test');
 * $params = array(
 *   'headers' => array(
 *     'content-type' => 'application/json',
 *     'authorization' => 'Bearer ' . $token,
 *   ),
 * );
 *
 * $request = $client->post('/post', $params);
 * $request->setBody(json_encode($payload));
 *
 * // Send request to the service
 * $response = $request->send();
 * $body = $response->getBody();
 *
 * print_r(json_decode((string) $body));
 */
