<?php

namespace Cast\Crypto\ECDSA\Tests;

use function Cast\Crypto\ECDSA\secp256k1\p_curve;
use function Cast\Crypto\ECDSA\secp256k1\N;
use function Cast\Crypto\ECDSA\secp256k1\GPoint;
use function Cast\Crypto\ECDSA\secp256k1\prefixCompressed;
use function Cast\Crypto\ECDSA\secp256k1\publicKey;
use function Cast\Crypto\ECDSA\secp256k1\publicKeyVerbose;
use function Cast\Crypto\ECDSA\secp256k1\publicKeyCoords;
use function Cast\Crypto\ECDSA\secp256k1\decompressPublicKey;
use function Cast\Crypto\ECDSA\secp256k1\hex;
use function Cast\Crypto\ECDSA\secp256k1\sign;
use function Cast\Crypto\ECDSA\secp256k1\verify;
use PHPUnit\Framework\TestCase;

class Secp256k1Test extends TestCase
{
    public function test_p_curve()
    {
        $this->assertEquals('115792089237316195423570985008687907853269984665640564039457584007908834671663', gmp_strval(p_curve()));
    }

    public function test_n()
    {
        $this->assertEquals('115792089237316195423570985008687907852837564279074904382605163141518161494337', gmp_strval(N()));
    }

    public function test_GPoint()
    {
        $this->assertEquals(
            [
                '55066263022277343669578718895168534326250603453777594175500187360389116729240',
                '32670510020758816978083085130507043184471273380659243275938904335757337482424',
            ],
            array_map('gmp_strval', GPoint())
        );
    }

    public function test_publicKeyCoords()
    {
        $this->assertEquals(
            [
                '36422191471907241029883925342251831624200921388586025344128047678873736520530',
                '20277110887056303803699431755396003735040374760118964734768299847012543114150',
            ],
            array_map('gmp_strval', publicKeyCoords("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"))
        );
    }

    public function test_hex()
    {
        $this->assertEquals('50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352', hex('36422191471907241029883925342251831624200921388586025344128047678873736520530'));
        $this->assertEquals('2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6', hex('20277110887056303803699431755396003735040374760118964734768299847012543114150'));

    }

    public function test_prefixCompressed()
    {
        $this->assertEquals('02', prefixCompressed('20277110887056303803699431755396003735040374760118964734768299847012543114150'));
        $this->assertEquals('03', prefixCompressed('1453714277448899330796875108471283983549338801323505622815336896137228845633'));
    }

    public function test_publicKey()
    {
        $this->assertEquals('0250863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352', publicKey('18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725'));
        $this->assertEquals('0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6', publicKey('18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725', false));
        $this->assertEquals('032A574EA59CAE80B09D6BA415746E9B031ABFBE83F149B43B37BE035B87164872', publicKey('79FE45D61339181238E49424E905446A35497A8ADEA8B7D5241A1E7F2C95A04D'));
        $this->assertEquals('042A574EA59CAE80B09D6BA415746E9B031ABFBE83F149B43B37BE035B87164872336C5EB647E891C98261C57C13098FA6AE68221363C68FF15841B86DAD60241', publicKey('79FE45D61339181238E49424E905446A35497A8ADEA8B7D5241A1E7F2C95A04D', false));
    }

    public function test_publicKeyVerbose()
    {
        $this->assertEquals(
            [
                'X' => '36422191471907241029883925342251831624200921388586025344128047678873736520530',
                'Y' => '20277110887056303803699431755396003735040374760118964734768299847012543114150',
                'xHex' => '50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352',
                'yHex' => '2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6',
                'compressed' => '0250863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352',
                'uncompressed' => '0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6',
            ],
            array_map(
                function ($prop) {
                    return $prop instanceof \GMP ? gmp_strval($prop) : $prop;
                },
                publicKeyVerbose('18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725')
            )
        );
    }

    public function test_decompressPublicKey()
    {
        $this->assertEquals('0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6', decompressPublicKey('0250863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352'));
    }

    public function test_sign()
    {
        $privateKey = '18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725';
        $message = "public data to sign";
        $messageHash = hash('sha256', $message); // hex, any algo
        $salt = '830769f9b99527c7ecc30ed760c33a93e61041de0707338f73b4cb05823ea052'; // the sign request id, onetime random number

        $this->assertEquals('be491708002b9ea80b4f09546f94c39b8865b94f2d0593eead293ef1ecc2f4bb', sign($salt, $messageHash, $privateKey));
    }

    public function test_verify()
    {
        $publicKey = '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352';
        $message = "public data to sign";
        $messageHash = hash('sha256', $message); // hex, any algo
        $salt = '830769f9b99527c7ecc30ed760c33a93e61041de0707338f73b4cb05823ea052'; // the sign request id, onetime random number
        $signature = 'be491708002b9ea80b4f09546f94c39b8865b94f2d0593eead293ef1ecc2f4bb';

        $this->assertEquals(true, verify($signature, $messageHash, $salt, $publicKey));
    }
}
