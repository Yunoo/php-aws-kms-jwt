PHP JWT token generator using AWS KMS for encryption
====================================================

### About AWS KMS JWT

- Utilizes AWS KMS data keys for JWT generation using an envelope encryption method.
- Supports PHP >=5.3 (excluding GCM and CCM cipher algorithms)

### Installing via Composer

You can install AWS KMS JWT using [Composer](http://getcomposer.org).

```bash
# Install Composer
curl -sS https://getcomposer.org/installer | php

# Add it as a dependency
php composer.phar require iweron/aws-kms-jwt
```

After installing, you need to require Composer's autoloader:

```php
require 'vendor/autoload.php';
```

Before using this lib, you will need to issue a spare AWS KMS master key. Check this article to figure out how to create one https://nsmith.net/aws-kms-cli
You can check an `examples` directory to get more info on usage.


### Envelope encryption

This lib implements envelope encryption with symmetric keys based on AWS KMS initially proposed by [Latacora](https://latacora.micro.blog/).

![Envelope encryptuon](https://d33wubrfki0l68.cloudfront.net/32691e7982d036efb3a00c379f0a831d9329e86f/3c352/assets-jekyll/blog/the-hardest-thing-about-data-encryption/symmetric-encryption-best-practices-491b688b0fe6d5215e2c9b16159a6edd9356f7cdf2b63eab5a85c7be58fbb35a.png)

*NB!* This repo does not have the code for token verification/decryption. You might need to implement it yourself as it is shown in the following diagram:
![Envelope decryption](https://d33wubrfki0l68.cloudfront.net/ad4511f80b20086363aad629aba69aa74d17621f/45323/assets-jekyll/blog/the-hardest-thing-about-data-encryption/symmetric-decryption-best-practices-3aafe0d89802ab192985d2d30df5d6e673f39aff548ee09a5e87059606c793be.png)


Reference: https://developer.okta.com/blog/2019/07/25/the-hardest-thing-about-data-encryption#data-encryption-key-management-solutions