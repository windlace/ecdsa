<?php

namespace Cast\Crypto\ECDSA\Tests;

use function Cast\Crypto\ECDSA\Conv\convBase;
use PHPUnit\Framework\TestCase;

class ConvTest extends TestCase
{
    function test_ConvBase()
    {
        // Convert '123' from decimal (base10) to octal (base8)
        $this->assertEquals('173', convBase('123', '0123456789', '01234567'));

        // Convert '70B1D707EAC2EDF4C6389F440C7294B51FFF57BB' from hexadecimal (base16) to binary (base2).
        $this->assertEquals('111000010110001110101110000011111101010110000101110110111110100110001100011100010011111010001000000110001110010100101001011010100011111111111110101011110111011', convBase('70B1D707EAC2EDF4C6389F440C7294B51FFF57BB', '0123456789ABCDEF', '01'));

        // Convert '1324523453243154324542341524315432113200203012' from senary (base6) to hexadecimal (base16).
        $this->assertEquals('1F9881BAD10454A8C23A838EF00F50', convBase('1324523453243154324542341524315432113200203012', '012345', '0123456789ABCDEF'));

        // Convert '355927353784509896715106760' from decimal (base10) to undecimal (base11) using "Christopher" as the numbers.
        $this->assertEquals('iihtspiphoeCrCeshhorsrrtrh', convBase('355927353784509896715106760','0123456789','Christopher'));

        // Convert'1C238Ab97132aAC84B72' from octodecimal (base18) using '0123456789aAbBcCdD' as the numbers
        // to undecimal (base11) using '~!@#$%^&*()' as the numbers.
        $this->assertEquals('!%~!!*&!~^!!&(&!~^@#@@@&', convBase('1C238Ab97132aAC84B72','0123456789aAbBcCdD', '~!@#$%^&*()'));
    }
}
