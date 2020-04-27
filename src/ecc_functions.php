<?php

declare(strict_types=1);

namespace Cast\Crypto\ECDSA\ECC;

use const Cast\BaseConv\BASE_16_UPPER;
use const Cast\BaseConv\BASE_2;
use function Cast\Crypto\ECDSA\Conv\convBase;

/**
 * @param   \GMP[]|int[]    $a
 * @param   \GMP|int        $A_CURVE
 * @param   \GMP|int        $P_CURVE
 * @return \GMP[]|int[]
 */
function ECdouble(array $a, $A_CURVE, $P_CURVE) : array
{
    $Lambda = ((3 * $a[0] * $a[0] + $A_CURVE) * gmp_invert((2 * $a[1]), $P_CURVE)) % $P_CURVE;
    $x = ($Lambda * $Lambda - 2 * $a[0]) % $P_CURVE;
    $y = ($Lambda * ($a[0] - $x) - $a[1]) % $P_CURVE;
    return [$x, $y];
}

/**
 * @param   \GMP[]|int[]    $a
 * @param   \GMP[]|int[]    $b
 * @param   \GMP|int[]      $P_CURVE
 * @return \GMP[]|int[]
 */
function ECadd(array $a, array $b, $P_CURVE) : array
{
    $Lambda = (($b[1] - $a[1]) * gmp_invert($b[0] - $a[0], $P_CURVE)) % $P_CURVE;
    $x = ($Lambda * $Lambda - $a[0] - $b[0]) % $P_CURVE;
    $y = ($Lambda * ($a[0] - $x) - $a[1]) % $P_CURVE;
    return [$x, $y];
}

/**
 * @param   string          $ScalarHex PrivateKey
 * @param   \GMP[]|int[]    $GPoint
 * @param   \GMP|int        $N
 * @param   \GMP|int        $A_CURVE
 * @param   \GMP|\int        $P_CURVE
 * @return \GMP[]|int[] array
 * @throws \Exception
 */
function EccMultiply($ScalarHex, $GPoint, $N, $A_CURVE, $P_CURVE) : array
{
    if (gmp_init($ScalarHex, 16) == 0 or gmp_init($ScalarHex, 16) >= $N) throw new \Exception("Invalid Scalar/Private Key");
    $ScalarBin = convBase(strtoupper($ScalarHex), BASE_16_UPPER, BASE_2);
    $Q=$GPoint;
    foreach (str_split(substr($ScalarBin, 1), 1) as $bit)
    {
        $Q = ECdouble($Q, $A_CURVE, $P_CURVE);
        if ($bit == "1") {
            $Q = ECadd($Q, $GPoint, $P_CURVE);
        }
    }

    return $Q;
}
