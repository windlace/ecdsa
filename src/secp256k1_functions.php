<?php

declare(strict_types=1);

namespace Cast\Crypto\ECDSA\secp256k1;

use const Cast\Crypto\ECDSA\Conv\BASE_10;
use const Cast\Crypto\ECDSA\Conv\BASE_16_UPPER;
use function Cast\Crypto\ECDSA\Conv\convBase;
use function Cast\Crypto\ECDSA\ECC\EccMultiply;

const P_CURVE = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";   // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
# These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve
const A_CURVE = 0x0000000000000000000000000000000000000000000000000000000000000000;
const B_CURVE = 0x0000000000000000000000000000000000000000000000000000000000000007;
const G_X     = "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const G_Y     = "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
const N       = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const H       = 0x01;
const PREFIX_COMPRESSED_EVEN = "02";
const PREFIX_COMPRESSED_ODD  = "03";
const PREFIX_UNCOMPRESSED    = "04";

function p_curve()
{
    return gmp_init(convBase(P_CURVE, BASE_16_UPPER, BASE_10));
}

function N()
{
    return gmp_init(convBase(N, BASE_16_UPPER, BASE_10));
}

function GPoint() : array
{
    return $GPoint = [gmp_init(G_X), gmp_init(G_Y)];
}

/**
 * @param $privateKey
 * @return array|\GMP[]|int[]
 * @throws \Exception
 */
function publicKeyCoords($privateKey)
{
    return EccMultiply($privateKey, GPoint(), N(), A_CURVE, P_CURVE);
}

function hex(string $value)
{
    return convBase(strtoupper($value), BASE_10, BASE_16_UPPER);
}

function prefixCompressed($PublicKeyY)
{
    return gmp_mod($PublicKeyY, 2) == 0 ? PREFIX_COMPRESSED_EVEN : PREFIX_COMPRESSED_ODD;
}

/**
 * @param $privateKey
 * @param bool $compressed
 * @return string
 * @throws \Exception
 */
function publicKey($privateKey, $compressed = true)
{
    [$PublicKeyX, $PublicKeyY] = publicKeyCoords($privateKey);
    $xHex = hex(gmp_strval($PublicKeyX));
    $yHex = hex(gmp_strval($PublicKeyY));

    return $compressed ? prefixCompressed($PublicKeyY).$xHex : PREFIX_UNCOMPRESSED.$xHex.$yHex;
}

/**
 * @param $privateKey
 * @return array
 * @throws \Exception
 */
function publicKeyVerbose($privateKey)
{
    [$PublicKeyX, $PublicKeyY] = publicKeyCoords($privateKey);
    $xHex = hex(gmp_strval($PublicKeyX));
    $yHex = hex(gmp_strval($PublicKeyY));

    return [
        'X' => $PublicKeyX,
        'Y' => $PublicKeyY,
        'xHex' => $xHex,
        'yHex' => $yHex,
        'compressed' => prefixCompressed($PublicKeyY).$xHex,
        'uncompressed' => PREFIX_UNCOMPRESSED.$xHex.$yHex,
    ];
}

/**
 * @param $publicKeyCompressedHex
 * @return string
 */
function decompressPublicKey($publicKeyCompressedHex)
{
    return decompressPublicKeyVerbose($publicKeyCompressedHex)['uncompressed'];
}

/**
 * @param $publicKeyCompressedHex
 * @return array
 */
function decompressPublicKeyVerbose($publicKeyCompressedHex)
{
    $prefix = substr($publicKeyCompressedHex, 0, 2);
    $x_hex = substr($publicKeyCompressedHex, 2, strlen($publicKeyCompressedHex));
    $x = gmp_init($x_hex, 16);

    $y_square = gmp_mod(gmp_mod(gmp_pow($x, 3), p_curve()) + 7, p_curve());
    $y_square_square_root = bcpowmod(gmp_strval($y_square), gmp_strval((p_curve() + 1) / 4), gmp_strval(p_curve()));

    if (($prefix == PREFIX_COMPRESSED_EVEN and $y_square_square_root & 1) or ($prefix == PREFIX_COMPRESSED_ODD and !($y_square_square_root & 1))) {
        $y = (-gmp_init($y_square_square_root)) % p_curve();
    }else {
        $y = gmp_init($y_square_square_root);
    }

    $computed_y_hex = \Cast\Crypto\ECDSA\Conv\convBase(gmp_strval($y), \Cast\Crypto\ECDSA\Conv\BASE_10, BASE_16_UPPER);

    return [
        'X' => $x,
        'Y' => $y,
        'xHex' => $x_hex,
        'yHex' => $computed_y_hex,
        'compressed' => prefixCompressed($y).$x_hex,
        'uncompressed' => PREFIX_UNCOMPRESSED.$x_hex.$computed_y_hex,
    ];
}
