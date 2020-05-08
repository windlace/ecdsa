<?php

declare(strict_types=1);

namespace Cast\Crypto\ECDSA\Conv;

const BASE_2  = '01';
const BASE_10 = '0123456789';
const BASE_16 = '0123456789abcdef';
const BASE_16_UPPER = '0123456789ABCDEF';
const BASE_58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function convBase($numberInput, $fromBaseInput, $toBaseInput) : string
{
    if ($fromBaseInput==$toBaseInput) return $numberInput;
    $fromBase = str_split($fromBaseInput,1);
    $toBase = str_split($toBaseInput,1);
    $number = str_split($numberInput,1);
    $fromLen=strlen($fromBaseInput);
    $toLen=strlen($toBaseInput);
    $numberLen=strlen($numberInput);
    $retval='';
    if ($toBaseInput == '0123456789')
    {
        $retval=0;
        for ($i = 1;$i <= $numberLen; $i++)
            $retval = bcadd((string)$retval, bcmul((string)array_search($number[$i-1], $fromBase),bcpow((string)$fromLen,(string)($numberLen-$i))));
        return $retval;
    }
    if ($fromBaseInput != '0123456789')
        $base10=convBase($numberInput, $fromBaseInput, '0123456789');
    else
        $base10 = $numberInput;
    if ($base10<strlen($toBaseInput))
        return $toBase[$base10];
    while($base10 != '0')
    {
        $retval = $toBase[bcmod($base10,(string)$toLen)].$retval;
        $base10 = bcdiv($base10,(string)$toLen,0);
    }
    return $retval;
}
