ECDSA
---
**Pure PHP-implementation without any extensions**

#### Install:
```php
composer require cast/ecdsa
```

#### Usage:
```php
<?php

use function Cast\Crypto\ECDSA\secp256k1\publicKey;
use function Cast\Crypto\ECDSA\secp256k1\sign;
use function Cast\Crypto\ECDSA\secp256k1\verify;

// key pair generation:
$privateKey = bin2hex(random_bytes(32)); // 18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725
$publicKey = publicKey($privateKey); // 0250863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352

// signature generation:
$message = "public data to sign";
$messageHash = hash('sha256', $message); // hex, any algo
$salt = bin2hex(random_bytes(32)); // the sign request id, onetime random number
$signature = sign($salt, $messageHash, $privateKey); // 78be7c53361d9bd7d32acc917d79aee05f633d3ae33a14040d179a6f4816aa3a

// signature verifying:
$verified = verify($signature, $messageHash, $salt, $publicKey); // true

```

### Links
* YouTube guide https://youtube.com/watch?v=wpLQZhqdPaA
* Python script https://github.com/wobine/blackboard101/blob/e991ea0b98fd26059bf3806e5749b5e5f737e791/EllipticCurvesPart4-PrivateKeyToPublicKey.py
* Bitcoin wiki secp256k1 https://en.bitcoin.it/wiki/Secp256k1
* Technical background of version 1 Bitcoin addresses https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses

