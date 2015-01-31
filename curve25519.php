<?php
/* Ported to PHP from Javascript by Alex Jones 1/29/15
 * Ported to JavaScript from Java 07/01/14.
 *
 * Ported from C to Java by Dmitry Skiba [sahn0], 23/02/08.
 * Original: http://cds.xs4all.nl:8081/ecdh/
 */
/* Generic 64-bit integer implementation of Curve25519 ECDH
 * Written by Matthijs van Duin, 200608242056
 * Public domain.
 *
 * Based on work by Daniel J Bernstein, http://cr.yp.to/ecdh.html
 */

class Curve25519 {

    //region Constants

    public $KEY_SIZE = 32;

    /* array length */
    public $UNPACKED_SIZE = 16;

    /* group order (a prime near 2^252+2^124) */
    public $ORDER = [
        237, 211, 245, 92,
        26, 99, 18, 88,
        214, 156, 247, 162,
        222, 249, 222, 20,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 16
    ];

    /* smallest multiple of the order that's >= 2^255 */
   public $ORDER_TIMES_8 = [
        104, 159, 174, 231,
        210, 24, 147, 192,
        178, 230, 188, 23,
        245, 206, 247, 166,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 128
    ];

    /* constants 2Gy and 1/(2Gy) */
    public $BASE_2Y = [
        22587, 610, 29883, 44076,
        15515, 9479, 25859, 56197,
        23910, 4462, 17831, 16322,
        62102, 36542, 52412, 16035
    ];

    public $BASE_R2Y = [
        5744, 16384, 61977, 54121,
        8776, 18501, 26522, 34893,
        23833, 5823, 55924, 58749,
        24147, 14085, 13606, 6080
    ];

    public $C1 = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    public $C9 = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    public $C486671 = [0x6D0F, 0x0007, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    public $C39420360 = [0x81C8, 0x0259, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    public $P25 = 33554431; /* (1 << 25) - 1 */
    public $P26 = 67108863; /* (1 << 26) - 1 */

    //#endregion

    //region Key Agreement

    /* Private key clamping
     *   k [out] your private key for key agreement
     *   k  [in]  32 random bytes
     */
    /*function clamp ($k) {
        $k[31] &= 0x7F;
        $k[31] |= 0x40;
        $k[ 0] &= 0xF8;
        return $k;
    }*/

    function clamp($secret)
    {
        $e = array_values(unpack('C32', $secret));
        $e[0]  &= 0xf8;
        $e[31] &= 0x7f;
        $e[31] |= 0x40;
        return $e;
    }

    //endregion

    //region radix 2^8 math

    function cpy32 ($d, $s) {
        for ($i = 0; $i < 32; $i++)
            $d[$i] = $s[$i];
    }

    /* p[m..n+m-1] = q[m..n+m-1] + z * x */
    /* n is the size of x */
    /* n+m is the size of p and q */
    function mula_small ($p, $q, $m, $x, $n, $z) {
        $m = $m | 0;
        $n = $n | 0;
        $z = $z | 0;

        $v = 0;
        for ($i = 0; $i < $n; ++$i) {
            $v += ($q[$i + $m] & 0xFF) + $z * ($x[$i] & 0xFF);
            $p[$i + $m] = ($v & 0xFF);
            $v >>= 8;
        }

        return $v;
    }

    /* p += x * y * z  where z is a small integer
     * x is size 32, y is size t, p is size 32+t
     * y is allowed to overlap with p+32 if you don't care about the upper half  */
    function mula32 ($p, $x, $y, $t, $z) {
        $t = $t | 0;
        $z = $z | 0;

        $n = 31;
        $w = 0;
        $i = 0;
        for (; $i < $t; $i++) {
            $zy = $z * ($y[$i] & 0xFF);
            $w += $this->mula_small($p, $p, $i, $x, $n, $zy) + ($p[$i+$n] & 0xFF) + $zy * ($x[$n] & 0xFF);
            $p[$i + $n] = $w & 0xFF;
            $w >>= 8;
        }
        $p[$i + $n] = ($w + ($p[$i + $n] & 0xFF)) & 0xFF;
        return $w >> 8;
    }

    /* divide r (size n) by d (size t), returning quotient q and remainder r
     * quotient is size n-t+1, remainder is size t
     * requires t > 0 && d[t-1] !== 0
     * requires that r[-1] and d[-1] are valid memory locations
     * q may overlap with r+t */
    function divmod ($q, $r, $n, $d, $t) {
        $n = $n | 0;
        $t = $t | 0;

        $rn = 0;
        $dt = ($d[$t - 1] & 0xFF) << 8;
        if ($t > 1)
            $dt |= ($d[$t - 2] & 0xFF);

        while ($n-- >= $t) {
            $z = ($rn << 16) | (($r[$n] & 0xFF) << 8);
            if ($n > 0)
                $z |= ($r[$n - 1] & 0xFF);

            $i = $n - $t + 1;
            $z /= $dt;
            $rn += $this->mula_small($r, $r, $i, $d, $t, -$z);
            $q[$i] = ($z + $rn) & 0xFF;
            /* rn is 0 or -1 (underflow) */
            $this->mula_small($r, $r, $i, $d, $t, -$rn);
            $rn = $r[$n] & 0xFF;
            $r[$n] = 0;
        }

        $r[$t-1] = $rn & 0xFF;
    }

    function numsize ($x, $n) {
        while ($n-- !== 0 && $x[$n] === 0) { }
        return $n + 1;
    }

    /* Returns x if a contains the gcd, y if b.
     * Also, the returned buffer contains the inverse of a mod b,
     * as 32-byte signed.
     * x and y must have 64 bytes space for temporary use.
     * requires that a[-1] and b[-1] are valid memory locations  */
    function egcd32 ($x, $y, $a, $b) {
        $a;
        $bn = 32;
        $qn;
        $i;
        for ($i = 0; $i < 32; $i++)
            $x[$i] = $y[$i] = 0;
        $x[0] = 1;
        $an = $this->numsize($a, 32);
        if ($an === 0)
            return $y; /* division by zero */
        $temp = array();
        while (true) {
            $qn = $bn - $an + 1;
            $this->divmod($temp, $b, $bn, $a, $an);
            $bn = $this->numsize($b, $bn);
            if ($bn === 0)
                return $x;
            $this->mula32($y, $x, $temp, $qn, -1);

            $qn = $an - $bn + 1;
            $this->divmod($temp, $a, $an, $b, $bn);
            $an = $this->numsize($a, $an);
            if ($an === 0)
                return $y;
            $this->mula32($x, $y, $temp, $qn, -1);
        }
    }

    //endregion

    //region radix 2^25.5 GF(2^255-19) math

    //region pack / unpack

    /* Convert to internal format from little-endian byte format */
    function unpack ($x, $m) {
        for ($i = 0; $i < $this->KEY_SIZE; $i += 2)
            $x[$i / 2] = $m[$i] & 0xFF | (($m[$i + 1] & 0xFF) << 8);
    }

    /* Check if reduced-form input >= 2^255-19 */
    function is_overflow ($x) {
        return (
            (($x[0] > $P26 - 19)) &&
                (($x[1] & $x[3] & $x[5] & $x[7] & $x[9]) === $this->P25) &&
                (($x[2] & $x[4] & $x[6] & $x[8]) === $this->P26)
            ) || ($x[9] > $this->P25);
    }

    /* Convert from internal format to little-endian byte format.  The
     * number must be in a reduced form which is output by the following ops:
     *     unpack, mul, sqr
     *     set --  if input in range 0 .. P25
     * If you're unsure if the number is reduced, first multiply it by 1.  */
    function pack ($x, $m) {
        for ($i = 0; $i < $this->UNPACKED_SIZE; ++$i) {
            $m[2 * $i] = $x[$i] & 0x00FF;
            $m[2 * $i + 1] = ($x[$i] & 0xFF00) >> 8;
        }
    }

    //endregion

    function createUnpackedArray () {
        return array();
    }

    /* Copy a number */
    function cpy (&$d, &$s) {
        for ($i = 0; $i < $this->UNPACKED_SIZE; ++$i)
            $d[$i] = $s[$i];
    }

    /* Set a number to value, which must be in range -185861411 .. 185861411 */
    function set ($d, $s) {
        $d[0] = $s;
        for ($i = 1; $i < $this->UNPACKED_SIZE; ++$i)
            $d[$i] = 0;
    }

    /* Add/subtract two numbers.  The inputs must be in reduced form, and the
     * output isn't, so to do another addition or subtraction on the output,
     * first multiply it by one to reduce it. */


    /* Multiply a number by a small integer in range -185861411 .. 185861411.
     * The output is in reduced form, the input x need not be.  x and xy may point
     * to the same buffer. */

    /* Multiply two numbers.  The output is in reduced form, the inputs need not be. */

    /* Square a number.  Optimization of  mul25519(x2, x, x)  */

    /* Calculates a reciprocal.  The output is in reduced form, the inputs need not
     * be.  Simply calculates  y = x^(p-2)  so it's not too fast. */
    /* When sqrtassist is true, it instead calculates y = x^((p-5)/8) */
    function recip ($y, $x, $sqrtassist) {
        $t0 = $this->createUnpackedArray();
        $t1 = $this->createUnpackedArray();
        $t2 = $this->createUnpackedArray();
        $t3 = $this->createUnpackedArray();
        $t4 = $this->createUnpackedArray();

        /* the chain for x^(2^255-21) is straight from djb's implementation */
        $i;
        $this->sqr($t1, $x); /*  2 === 2 * 1 */
        $this->sqr($t2, $t1); /*  4 === 2 * 2    */
        $this->sqr($t0, $t2); /*  8 === 2 * 4    */
        $this->mul($t2, $t0, $x); /*  9 === 8 + 1 */
        $this->mul($t0, $t2, $t1); /* 11 === 9 + 2    */
        $this->sqr($t1, $t0); /* 22 === 2 * 11   */
        $this->mul($t3, $t1, $t2); /* 31 === 22 + 9 === 2^5   - 2^0   */
        $this->sqr($t1, $t3); /* 2^6   - 2^1 */
        $this->sqr($t2, $t1); /* 2^7   - 2^2 */
        $this->sqr($t1, $t2); /* 2^8   - 2^3 */
        $this->sqr($t2, $t1); /* 2^9   - 2^4 */
        $this->sqr($t1, $t2); /* 2^10  - 2^5 */
        $this->mul($t2, $t1, $t3); /* 2^10  - 2^0 */
        $this->sqr($t1, $t2); /* 2^11  - 2^1 */
        $this->sqr($t3, $t1); /* 2^12  - 2^2 */
        for ($i = 1; $i < 5; $i++) {
            $this->sqr($t1, $t3);
            $this->sqr($t3, $t1);
        } /* t3 */ /* 2^20  - 2^10  */
        $this->mul($t1, $t3, $t2); /* 2^20  - 2^0 */
        $this->sqr($t3, $t1); /* 2^21  - 2^1 */
        $this->sqr($t4, $t3); /* 2^22  - 2^2 */
        for ($i = 1; $i < 10; $i++) {
            $this->sqr($t3, $t4);
            $this->sqr($t4, $t3);
        } /* t4 */ /* 2^40  - 2^20  */
        $this->mul($t3, $t4, $t1); /* 2^40  - 2^0 */
        for ($i = 0; $i < 5; $i++) {
            $this->sqr($t1, $t3);
            $this->sqr($t3, $t1);
        } /* t3 */ /* 2^50  - 2^10  */
        $this->mul($t1, $t3, $t2); /* 2^50  - 2^0 */
        $this->sqr($t2, $t1); /* 2^51  - 2^1 */
        $this->sqr($t3, $t2); /* 2^52  - 2^2 */
        for ($i = 1; $i < 25; $i++) {
            $this->sqr($t2, $t3);
            $this->sqr($t3, $t2);
        } /* t3 */ /* 2^100 - 2^50 */
        $this->mul($t2, $t3, $t1); /* 2^100 - 2^0 */
        $this->sqr($t3, $t2); /* 2^101 - 2^1 */
        $this->sqr($t4, $t3); /* 2^102 - 2^2 */
        for ($i = 1; $i < 50; $i++) {
            $this->sqr($t3, $t4);
            $this->sqr($t4, $t3);
        } /* t4 */ /* 2^200 - 2^100 */
        $this->mul($t3, $t4, $t2); /* 2^200 - 2^0 */
        for ($i = 0; $i < 25; $i++) {
            $this->sqr($t4, $t3);
            $this->sqr($t3, $t4);
        } /* t3 */ /* 2^250 - 2^50  */
        $this->mul($t2, $t3, $t1); /* 2^250 - 2^0 */
        $this->sqr($t1, $t2); /* 2^251 - 2^1 */
        $this->sqr($t2, $t1); /* 2^252 - 2^2 */
        if ($sqrtassist !== 0) {
            $this->mul($y, $x, $t2); /* 2^252 - 3 */
        } else {
            $this->sqr($t1, $t2); /* 2^253 - 2^3 */
            $this->sqr($t2, $t1); /* 2^254 - 2^4 */
            $this->sqr($t1, $t2); /* 2^255 - 2^5 */
            $this->mul($y, $t1, $t0); /* 2^255 - 21   */
        }
    }

    /* checks if x is "negative", requires reduced input */
    function is_negative ($x) {
        $isOverflowOrNegative = $this->is_overflow($x) || $x[9] < 0;
        $leastSignificantBit = $x[0] & 1;
        return (($isOverflowOrNegative ? 1 : 0) ^ $leastSignificantBit) & 0xFFFFFFFF;
    }

    /* a square root */
    function sqr ($x, $u) {
        $v = $this->createUnpackedArray();
        $t1 = $this->createUnpackedArray();
        $t2 = $this->createUnpackedArray();

        $this->add($t1, $u, $u); /* t1 = 2u       */
        $this->recip($v, $t1, 1); /* v = (2u)^((p-5)/8)  */
        $this->sqr($x, $v); /* x = v^2       */
        $this->mul($t2, $t1, $x); /* t2 = 2uv^2       */
        $this->sub($t2, $t2, $C1); /* t2 = 2uv^2-1        */
        $this->mul($t1, $v, $t2); /* t1 = v(2uv^2-1)  */
        $this->mul($x, $u, $t1); /* x = uv(2uv^2-1)   */
    }

    //endregion

    //region JavaScript Fast Math

    function c255lsqr8h ($a7, $a6, $a5, $a4, $a3, $a2, $a1, $a0) {
        $r = array();
        $v;
        $r[0] = ($v = $a0*$a0) & 0xFFFF;
        $r[1] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a1) & 0xFFFF;
        $r[2] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a2 + $a1*$a1) & 0xFFFF;
        $r[3] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a3 + 2*$a1*$a2) & 0xFFFF;
        $r[4] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a4 + 2*$a1*$a3 + $a2*$a2) & 0xFFFF;
        $r[5] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a5 + 2*$a1*$a4 + 2*$a2*$a3) & 0xFFFF;
        $r[6] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a6 + 2*$a1*$a5 + 2*$a2*$a4 + $a3*$a3) & 0xFFFF;
       $r[7] = ($v = (($v / 0x10000) | 0) + 2*$a0*$a7 + 2*$a1*$a6 + 2*$a2*$a5 + 2*$a3*$a4) & 0xFFFF;
        $r[8] = ($v = (($v / 0x10000) | 0) + 2*$a1*$a7 + 2*$a2*$a6 + 2*$a3*$a5 + $a4*$a4) & 0xFFFF;
        $r[9] = ($v = (($v / 0x10000) | 0) + 2*$a2*a7 + 2*$a3*$a6 + 2*$a4*$a5) & 0xFFFF;
        $r[10] = ($v = (($v / 0x10000) | 0) + 2*$a3*a7 + 2*$a4*$a6 + $a5*$a5) & 0xFFFF;
        $r[11] = ($v = (($v / 0x10000) | 0) + 2*$a4*a7 + 2*$a5*$a6) & 0xFFFF;
        $r[12] = ($v = (($v / 0x10000) | 0) + 2*$a5*a7 + $a6*$a6) & 0xFFFF;
        $r[13] = ($v = (($v / 0x10000) | 0) + 2*$a6*a7) & 0xFFFF;
        $r[14] = ($v = (($v / 0x10000) | 0) + $a7*$a7) & 0xFFFF;
        $r[15] = (($v / 0x10000) | 0);
        return $r;
    }

    function sqrt ($r, $a) {
        $x = $this->c255lsqr8h($a[15], $a[14], $a[13], $a[12], $a[11], $a[10], $a[9], $a[8]);
        $z = $this->c255lsqr8h($a[7], $a[6], $a[5], $a[4], $a[3], $a[2], $a[1], $a[0]);
        $y = $this->c255lsqr8h($a[15] + $a[7], $a[14] + $a[6], $a[13] + $a[5], $a[12] + $a[4], $a[11] + $a[3], $a[10] + $a[2], $a[9] + $a[1], $a[8] + $a[0]);

        $v;
        $r[0] = ($v = 0x800000 + $z[0] + ($y[8] -$x[8] -$z[8] + $x[0] -0x80) * 38) & 0xFFFF;
        $r[1] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[1] + ($y[9] -$x[9] -$z[9] + $x[1]) * 38) & 0xFFFF;
        $r[2] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[2] + ($y[10] -$x[10] -$z[10] + $x[2]) * 38) & 0xFFFF;
        $r[3] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[3] + ($y[11] -$x[11] -$z[11] + $x[3]) * 38) & 0xFFFF;
        $r[4] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[4] + ($y[12] -$x[12] -$z[12] + $x[4]) * 38) & 0xFFFF;
        $r[5] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[5] + ($y[13] -$x[13] -$z[13] + $x[5]) * 38) & 0xFFFF;
        $r[6] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[6] + ($y[14] -$x[14] -$z[14] + $x[6]) * 38) & 0xFFFF;
        $r[7] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[7] + ($y[15] -$x[15] -$z[15] + $x[7]) * 38) & 0xFFFF;
        $r[8] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[8] + $y[0] -$x[0] -$z[0] + $x[8] * 38) & 0xFFFF;
        $r[9] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[9] + $y[1] -$x[1] -$z[1] + $x[9] * 38) & 0xFFFF;
        $r[10] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[10] + $y[2] -$x[2] -$z[2] + $x[10] * 38) & 0xFFFF;
        $r[11] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[11] + $y[3] -$x[3] -$z[3] + $x[11] * 38) & 0xFFFF;
        $r[12] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[12] + $y[4] -$x[4] -$z[4] + $x[12] * 38) & 0xFFFF;
        $r[13] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[13] + $y[5] -$x[5] -$z[5] + $x[13] * 38) & 0xFFFF;
        $r[14] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[14] + $y[6] -$x[6] -$z[6] + $x[14] * 38) & 0xFFFF;
        $r15 = 0x7fff80 + (($v / 0x10000) | 0) + $z[15] + $y[7] -$x[7] -$z[7] + $x[15] * 38;
        $this->c255lreduce($r, $r15);
    }

    function c255lmul8h ($a7, $a6, $a5, $a4, $a3, $a2, $a1, $a0, $b7, $b6, $b5, $b4, $b3, $b2, $b1, $b0) {
        $r = [];
        $v;
        $r[0] = ($v = $a0*$b0) & 0xFFFF;
        $r[1] = ($v = (($v / 0x10000) | 0) + $a0*$b1 + $a1*$b0) & 0xFFFF;
        $r[2] = ($v = (($v / 0x10000) | 0) + $a0*$b2 + $a1*$b1 + $a2*$b0) & 0xFFFF;
        $r[3] = ($v = (($v / 0x10000) | 0) + $a0*$b3 + $a1*$b2 + $a2*$b1 + $a3*$b0) & 0xFFFF;
        $r[4] = ($v = (($v / 0x10000) | 0) + $a0*$b4 + $a1*$b3 + $a2*$b2 + $a3*$b1 + $a4*$b0) & 0xFFFF;
        $r[5] = ($v = (($v / 0x10000) | 0) + $a0*$b5 + $a1*$b4 + $a2*$b3 + $a3*$b2 + $a4*$b1 + $a5*$b0) & 0xFFFF;
        $r[6] = ($v = (($v / 0x10000) | 0) + $a0*$b6 + $a1*$b5 + $a2*$b4 + $a3*$b3 + $a4*$b2 + $a5*$b1 + $a6*$b0) & 0xFFFF;
        $r[7] = ($v = (($v / 0x10000) | 0) + $a0*$b7 + $a1*$b6 + $a2*$b5 + $a3*$b4 + $a4*$b3 + $a5*$b2 + $a6*$b1 + $a7*$b0) & 0xFFFF;
        $r[8] = ($v = (($v / 0x10000) | 0) + $a1*$b7 + $a2*$b6 + $a3*$b5 + $a4*$b4 + $a5*$b3 + $a6*$b2 + $a7*$b1) & 0xFFFF;
        $r[9] = ($v = (($v / 0x10000) | 0) + $a2*$b7 + $a3*$b6 + $a4*$b5 + $a5*$b4 + $a6*$b3 + $a7*$b2) & 0xFFFF;
        $r[10] = ($v = (($v / 0x10000) | 0) + $a3*$b7 + $a4*$b6 + $a5*$b5 + $a6*$b4 + $a7*$b3) & 0xFFFF;
        $r[11] = ($v = (($v / 0x10000) | 0) + $a4*$b7 + $a5*$b6 + $a6*$b5 + $a7*$b4) & 0xFFFF;
        $r[12] = ($v = (($v / 0x10000) | 0) + $a5*$b7 + $a6*$b6 + $a7*$b5) & 0xFFFF;
        $r[13] = ($v = (($v / 0x10000) | 0) + $a6*$b7 + $a7*$b6) & 0xFFFF;
        $r[14] = ($v = (($v / 0x10000) | 0) + $a7*$b7) & 0xFFFF;
        $r[15] = (($v / 0x10000) | 0);
        return r;
    }

    function mul ($r, $a, $b) {
        // Karatsuba multiplication scheme: x*y = (b^2+b)*x1*y1 - b*(x1-x0)*(y1-y0) + (b+1)*x0*y0
        $x = $this->c255lmul8h($a[15], $a[14], $a[13], $a[12], $a[11], $a[10], $a[9], $a[8], $b[15], $b[14], $b[13], $b[12], $b[11], $b[10], $b[9], $b[8]);
        $z = $this->c255lmul8h($a[7], $a[6], $a[5], $a[4], $a[3], $a[2], $a[1], $a[0], $b[7], $b[6], $b[5], $b[4], $b[3], $b[2], $b[1], $b[0]);
        $y = $this->c255lmul8h($a[15] + $a[7], $a[14] + $a[6], $a[13] + $a[5], $a[12] + $a[4], $a[11] + $a[3], $a[10] + $a[2], $a[9] + $a[1], $a[8] + $a[0],
            $b[15] + $b[7], $b[14] + $b[6], $b[13] + $b[5], $b[12] + $b[4], $b[11] + $b[3], $b[10] + $b[2], $b[9] + $b[1], $b[8] + $b[0]);

        $v;
        $r[0] = ($v = 0x800000 + $z[0] + ($y[8] -$x[8] -$z[8] + $x[0] -0x80) * 38) & 0xFFFF;
        $r[1] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[1] + ($y[9] -$x[9] -$z[9] + $x[1]) * 38) & 0xFFFF;
        $r[2] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[2] + ($y[10] -$x[10] -$z[10] + $x[2]) * 38) & 0xFFFF;
        $r[3] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[3] + ($y[11] -$x[11] -$z[11] + $x[3]) * 38) & 0xFFFF;
        $r[4] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[4] + ($y[12] -$x[12] -$z[12] + $x[4]) * 38) & 0xFFFF;
        $r[5] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[5] + ($y[13] -$x[13] -$z[13] + $x[5]) * 38) & 0xFFFF;
        $r[6] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[6] + ($y[14] -$x[14] -$z[14] + $x[6]) * 38) & 0xFFFF;
        $r[7] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[7] + ($y[15] -$x[15] -$z[15] + $x[7]) * 38) & 0xFFFF;
        $r[8] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[8] + $y[0] -$x[0] -$z[0] + $x[8] * 38) & 0xFFFF;
        $r[9] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[9] + $y[1] -$x[1] -$z[1] + $x[9] * 38) & 0xFFFF;
        $r[10] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[10] + $y[2] -$x[2] -$z[2] + $x[10] * 38) & 0xFFFF;
        $r[11] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[11] + $y[3] -$x[3] -$z[3] + $x[11] * 38) & 0xFFFF;
        $r[12] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[12] + $y[4] -$x[4] -$z[4] + $x[12] * 38) & 0xFFFF;
        $r[13] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[13] + $y[5] -$x[5] -$z[5] + $x[13] * 38) & 0xFFFF;
        $r[14] = ($v = 0x7fff80 + (($v / 0x10000) | 0) + $z[14] + $y[6] -$x[6] -$z[6] + $x[14] * 38) & 0xFFFF;
        $r15 = 0x7fff80 + (($v / 0x10000) | 0) + $z[15] + $y[7] -$x[7] -$z[7] + $x[15] * 38;
        $this->c255lreduce($r, $r15);
    }

    function c255lreduce ($a, $a15) {
        $v = $a15;
        $a[15] = $v & 0x7FFF;
        $v = (($v / 0x8000) | 0) * 19;
        for ($i = 0; $i <= 14; ++$i) {
            $a[$i] = ($v += $a[$i]) & 0xFFFF;
            $v = (($v / 0x10000) | 0);
        }

        $a[15] += $v;
    }

    function add ($r, $a, $b) {
        $v;
        $r[0] = ($v = ((($a[15] / 0x8000) | 0) + (($b[15] / 0x8000) | 0)) * 19 + $a[0] + $b[0]) & 0xFFFF;
        for ($i = 1; $i <= 14; ++$i)
            $r[$i] = ($v = (($v / 0x10000) | 0) + $a[$i] + $b[$i]) & 0xFFFF;

        $r[15] = (($v / 0x10000) | 0) + ($a[15] & 0x7FFF) + ($b[15] & 0x7FFF);
    }

    function sub ($r, $a, $b) {
        $v;
        $r[0] = ($v = 0x80000 + ((($a[15] / 0x8000) | 0) - (($b[15] / 0x8000) | 0) - 1) * 19 + $a[0] - $b[0]) & 0xFFFF;
        for ($i = 1; $i <= 14; ++$i)
            $r[$i] = ($v = (($v / 0x10000) | 0) + 0x7fff8 + $a[$i] - $b[$i]) & 0xFFFF;

        $r[15] = (($v / 0x10000) | 0) + 0x7ff8 + ($a[15] & 0x7FFF) - ($b[15] & 0x7FFF);
    }

    function mul_small ($r, $a, $m) {
        $v;
        $r[0] = ($v = $a[0] * $m) & 0xFFFF;
        for ($i = 1; $i <= 14; ++$i)
            $r[i] = ($v = (($v / 0x10000) | 0) + $a[$i]*$m) & 0xFFFF;

        $r15 = (($v / 0x10000) | 0) + $a[15]*$m;
        $this->c255lreduce($r, $r15);
    }

    //endregion

    /********************* Elliptic curve *********************/

    /* y^2 = x^3 + 486662 x^2 + x  over GF(2^255-19) */

    /* t1 = ax + az
     * t2 = ax - az  */
    function mont_prep ($t1, $t2, $ax, $az) {
        $this->add($t1, $ax, $az);
        $this->sub($t2, $ax, $az);
    }

    /* A = P + Q   where
     *  X(A) = ax/az
     *  X(P) = (t1+t2)/(t1-t2)
     *  X(Q) = (t3+t4)/(t3-t4)
     *  X(P-Q) = dx
     * clobbers t1 and t2, preserves t3 and t4  */
    function mont_add ($t1, $t2, $t3, $t4, $ax, $az, $dx) {
        $this->mul($ax, $t2, $t3);
        $this->mul($az, $t1, $t4);
        $this->add($t1, $ax, $az);
        $this->sub($t2, $ax, $az);
        $this->sqr($ax, $t1);
        $this->sqr($t1, $t2);
        $this->mul($az, $t1, $dx);
    }

    /* B = 2 * Q   where
     *  X(B) = bx/bz
     *  X(Q) = (t3+t4)/(t3-t4)
     * clobbers t1 and t2, preserves t3 and t4  */
    function mont_dbl ($t1, $t2, $t3, $t4, $bx, $bz) {
        $this->sqr($t1, $t3);
        $this->sqr($t2, $t4);
        $this->mul($bx, $t1, $t2);
        $this->sub($t2, $t1, $t2);
        $this->mul_small($bz, $t2, 121665);
        $this->add($t1, $t1, $bz);
        $this->mul($bz, $t1, $t2);
    }

    /* Y^2 = X^3 + 486662 X^2 + X
     * t is a temporary  */
    function x_to_y2 ($t, $y2, $x) {
        $this->sqr($t, $x);
        $this->mul_small($y2, $x, 486662);
        $this->add($t, $t, $y2);
        $this->add($t, $t, $C1);
        $this->mul($y2, $t, $x);
    }

    /* P = kG   and  s = sign(P)/k  */
    function core ($Px, $s, $k, $Gx) {
        $dx = $this->createUnpackedArray();
        $t1 = $this->createUnpackedArray();
        $t2 = $this->createUnpackedArray();
        $t3 = $this->createUnpackedArray();
        $t4 = $this->createUnpackedArray();
        $x = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $z = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $i;
        $j;

        /* unpack the base */
        if ($Gx !== null)
            $this->unpack($dx, $Gx);
        else
            $this->set($dx, 9);

        /* 0G = point-at-infinity */
        $this->set($x[0], 1);
        $this->set($z[0], 0);

        /* 1G = G */
        $this->cpy($x[1], $dx);
        $this->set($z[1], 1);

        for ($i = 32; $i-- !== 0;) {
            for ($j = 8; $j-- !== 0;) {
                /* swap arguments depending on bit */
                $bit1 = ($k[$i] & 0xFF) >> $j & 1;
                $bit0 = ~($k[$i] & 0xFF) >> $j & 1;
                $ax = $x[$bit0];
                $az = $z[$bit0];
                $bx = $x[$bit1];
                $bz = $z[$bit1];

                /* a' = a + b   */
                /* b' = 2 b */
                $this->mont_prep($t1, $t2, $ax, $az);
                $this->mont_prep($t3, $t4, $bx, $bz);
                $this->mont_add($t1, $t2, $t3, $t4, $ax, $az, $dx);
                $this->mont_dbl($t1, $t2, $t3, $t4, $bx, $bz);
            }
        }

        $this->recip($t1, $z[0], 0);
        $this->mul($dx, $x[0], $t1);

        $this->pack($dx, $Px);

        /* calculate s such that s abs(P) = G  .. assumes G is std base point */
        if ($s !== null) {
            $this->x_to_y2($t2, $t1, $dx); /* t1 = Py^2  */
            $this->recip($t3, $z[1], 0); /* where Q=P+G ... */
            $this->mul($t2, $x[1], $t3); /* t2 = Qx  */
            $this->add($t2, $t2, $dx); /* t2 = Qx + Px  */
            $this->add($t2, $t2, $C486671); /* t2 = Qx + Px + Gx + 486662  */
            $this->sub($dx, $dx, $C9); /* dx = Px - Gx  */
            $this->sqr($t3, $dx); /* t3 = (Px - Gx)^2  */
            $this->mul($dx, $t2, $t3); /* dx = t2 (Px - Gx)^2  */
            $this->sub($dx, $dx, $t1); /* dx = t2 (Px - Gx)^2 - Py^2  */
            $this->sub($dx, $dx, $C39420360); /* dx = t2 (Px - Gx)^2 - Py^2 - Gy^2  */
            $this->mul($t1, $dx, $BASE_R2Y); /* t1 = -Py  */

            if ($this->is_negative($t1) !== 0)    /* sign is 1, so just copy  */
                $this->cpy32($s, $k);
            else            /* sign is -1, so negate  */
                $this->mula_small($s, $this->ORDER_TIMES_8, 0, $k, 32, -1);

            /* reduce s mod q
             * (is this needed?  do it just in case, it's fast anyway) */
            //divmod((dstptr) t1, s, 32, order25519, 32);

            /* take reciprocal of s mod q */
            $temp1 = array();
            $temp2 = array();
            $temp3 = array();
            $this->cpy32($temp1, $this->ORDER);
            $this->cpy32($s, $this->egcd32($temp2, $temp3, $s, $temp1));
            if (($s[31] & 0x80) !== 0)
                $this->mula_small($s, $s, 0, $ORDER, 32, 1);

        }
    }

    /********* DIGITAL SIGNATURES *********/

    /* deterministic EC-KCDSA
     *
     *    s is the private key for signing
     *    P is the corresponding public key
     *    Z is the context data (signer public key or certificate, etc)
     *
     * signing:
     *
     *    m = hash(Z, message)
     *    x = hash(m, s)
     *    keygen25519(Y, NULL, x);
     *    r = hash(Y);
     *    h = m XOR r
     *    sign25519(v, h, x, s);
     *
     *    output (v,r) as the signature
     *
     * verification:
     *
     *    m = hash(Z, message);
     *    h = m XOR r
     *    verify25519(Y, v, h, P)
     *
     *    confirm  r === hash(Y)
     *
     * It would seem to me that it would be simpler to have the signer directly do
     * h = hash(m, Y) and send that to the recipient instead of r, who can verify
     * the signature by checking h === hash(m, Y).  If there are any problems with
     * such a scheme, please let me know.
     *
     * Also, EC-KCDSA (like most DS algorithms) picks x random, which is a waste of
     * perfectly good entropy, but does allow Y to be calculated in advance of (or
     * parallel to) hashing the message.
     */

    /* Signature generation primitive, calculates (x-h)s mod q
     *   h  [in]  signature hash (of message, signature pub key, and context data)
     *   x  [in]  signature private key
     *   s  [in]  private key for signing
     * returns signature value on success, undefined on failure (use different x or h)
     */

    function sign ($h, $x, $s) {
        // v = (x - h) s  mod q
        $w;
        $i;
        $h1 = array();
        $x1 = array();
        $tmp1 = array();
        $tmp2 = array();

        // Don't clobber the arguments, be nice!
        $this->cpy32($h1, $h);
        $this->cpy32($x1, $x);

        // Reduce modulo group order
        $tmp3 = array();
        $this->divmod($tmp3, $h1, 32, $this->ORDER, 32);
        $this->divmod($tmp3, $x1, 32, $this->ORDER, 32);

        // v = x1 - h1
        // If v is negative, add the group order to it to become positive.
        // If v was already positive we don't have to worry about overflow
        // when adding the order because v < ORDER and 2*ORDER < 2^256
        $v = array();
        $this->mula_small($v, $x1, 0, $h1, 32, -1);
        $this->mula_small($v, $v , 0, $this->ORDER, 32, 1);

        // tmp1 = (x-h)*s mod q
        $this->mula32($tmp1, $v, $s, 32, 1);
        $this->divmod($tmp2, $tmp1, 64, $this->ORDER, 32);

        for ($w = 0, $i = 0; $i < 32; $i++)
            $w |= $v[$i] = $tmp1[$i];

        return $w !== 0 ? $v : undefined;
    }

    /* Signature verification primitive, calculates Y = vP + hG
     *   v  [in]  signature value
     *   h  [in]  signature hash
     *   P  [in]  public key
     *   Returns signature public key
     */
    function verify ($v, $h, $P) {
        /* Y = v abs(P) + h G  */
        $d = array();
        $p = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $s = [$this->createUnpackedArray(), $this->createUnpackedArray()];
        $yx = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];
        $yz = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];
        $t1 = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];
        $t2 = [$this->createUnpackedArray(), $this->createUnpackedArray(), $this->createUnpackedArray()];

        $vi = 0;
        $hi = 0;
        $di = 0;
        $nvh = 0;
        $i; 
        $j;
        $k;

        /* set p[0] to G and p[1] to P  */

        $this->set($p[0], 9);
        $this->unpack($p[1], P);

        /* set s[0] to P+G and s[1] to P-G  */

        /* s[0] = (Py^2 + Gy^2 - 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */
        /* s[1] = (Py^2 + Gy^2 + 2 Py Gy)/(Px - Gx)^2 - Px - Gx - 486662  */

        $this->x_to_y2($t1[0], $t2[0], $p[1]); /* t2[0] = Py^2  */
        $this->sqrt($t1[0], $t2[0]); /* t1[0] = Py or -Py  */
        $j = $this->is_negative($t1[0]); /*      ... check which  */
        $this->add($t2[0], $t2[0], $this->C39420360); /* $t2[0] = Py^2 + Gy^2  */
        $this->mul($t2[1], $this->BASE_2Y, $t1[0]); /* $t2[1] = 2 Py Gy or -2 Py Gy  */
        $this->sub($t1[$j], $t2[0], $t2[1]); /* $t1[0] = Py^2 + Gy^2 - 2 Py Gy  */
        $this->add($t1[1 - $j], $t2[0], $t2[1]); /* $t1[1] = Py^2 + Gy^2 + 2 Py Gy  */
        $this->cpy($t2[0], $p[1]); /* $t2[0] = Px  */
        $this->sub($t2[0], $t2[0], $C9); /* $t2[0] = Px - Gx  */
        $this->sqr($t2[1], $t2[0]); /* $t2[1] = (Px - Gx)^2  */
        $this->recip($t2[0], $t2[1], 0); /* $t2[0] = 1/(Px - Gx)^2  */
        $this->mul($s[0], $t1[0], $t2[0]); /* $s[0] = $t1[0]/(Px - Gx)^2  */
        $this->sub($s[0], $s[0], $p[1]); /* $s[0] = $t1[0]/(Px - Gx)^2 - Px  */
        $this->sub($s[0], $s[0], $this->C486671); /* $s[0] = X(P+G)  */
        $this->mul($s[1], $t1[1], $t2[0]); /* $s[1] = $t1[1]/(Px - Gx)^2  */
        $this->sub($s[1], $s[1], $p[1]); /* $s[1] = $t1[1]/(Px - Gx)^2 - Px  */
        $this->sub($s[1], $s[1], $this->C486671); /* $s[1] = X(P-G)  */
        $this->mul_small($s[0], $s[0], 1); /* reduce $s[0] */
        $this->mul_small($s[1], $s[1], 1); /* reduce $s[1] */

        /* prepare the chain  */
        for ($i = 0; $i < 32; $i++) {
            $vi = ($vi >> 8) ^ ($v[$i] & 0xFF) ^ (($v[$i] & 0xFF) << 1);
            $hi = ($hi >> 8) ^ ($h[$i] & 0xFF) ^ (($h[$i] & 0xFF) << 1);
            $nvh = ~($vi ^ $hi);
            $di = ($nvh & ($di & 0x80) >> 7) ^ $vi;
            $di ^= $nvh & ($di & 0x01) << 1;
            $di ^= $nvh & ($di & 0x02) << 1;
            $di ^= $nvh & ($di & 0x04) << 1;
            $di ^= $nvh & ($di & 0x08) << 1;
            $di ^= $nvh & ($di & 0x10) << 1;
            $di ^= $nvh & ($di & 0x20) << 1;
            $di ^= $nvh & ($di & 0x40) << 1;
            $d[$i] = $di & 0xFF;
        }

        $di = (($nvh & ($di & 0x80) << 1) ^ $vi) >> 8;

        /* initialize state */
        $this->set($yx[0], 1);
        $this->cpy($yx[1], $p[$di]);
        $this->cpy($yx[2], $s[0]);
        $this->set($yz[0], 0);
        $this->set($yz[1], 1);
        $this->set($yz[2], 1);

        /* y[0] is (even)P + (even)G
         * y[1] is (even)P + (odd)G  if current d-bit is 0
         * y[1] is (odd)P + (even)G  if current d-bit is 1
         * y[2] is (odd)P + (odd)G
         */

        $vi = 0;
        $hi = 0;

        /* and go for it! */
        for ($i = 32; $i-- !== 0;) {
            $vi = ($vi << 8) | ($v[$i] & 0xFF);
            $hi = ($hi << 8) | ($h[$i] & 0xFF);
            $di = ($di << 8) | ($d[$i] & 0xFF);

            for ($j = 8; $j-- !== 0;) {
                $this->mont_prep($t1[0], $t2[0], $yx[0], $yz[0]);
                $this->mont_prep($t1[1], $t2[1], $yx[1], $yz[1]);
                $this->mont_prep($t1[2], $t2[2], $yx[2], $yz[2]);

                $k = (($vi ^ $vi >> 1) >> $j & 1)
                    + (($hi ^ $hi >> 1) >> $j & 1);
                $this->mont_dbl($yx[2], $yz[2], $t1[$k], $t2[$k], $yx[0], yz[0]);

                $k = ($di >> $j & 2) ^ (($di >> $j & 1) << 1);
                $this->mont_add($t1[1], $t2[1], $t1[$k], $t2[$k], $yx[1], $yz[1],
                    $p[$di >> $j & 1]);

                $this->mont_add($t1[2], $t2[2], $t1[0], $t2[0], $yx[2], $yz[2],
                    $s[(($vi ^ $hi) >> $j & 2) >> 1]);
            }
        }

        $k = ($vi & 1) + ($hi & 1);
        $this->recip($t1[0], $yz[$k], 0);
        $this->mul($t1[1], $yx[$k], $t1[0]);

        $Y = array();
        $this->pack($t1[1], $Y);
        return $Y;
    }

    /* Key-pair generation
     *   P  [out] your public key
     *   s  [out] your private key for signing
     *   k  [out] your private key for key agreement
     *   k  [in]  32 random bytes
     * s may be NULL if you don't care
     *
     * WARNING: if s is not NULL, this function has data-dependent timing */
    function keygen ($k) {
        $P = array();
        $s = array();
        $this->clamp($k);
        $this->core($P, $s, $k, null);

        return json_decode('{ "p": "$P", "s": "$s", "k": "$k" }');
    }

}

if (!function_exists('curve25519_sign')) {
    function curve25519_sign($h, $x, $s)
    {
        return (new Curve25519)->sign($h, $x, $s);
    }
    function curve25519_verify($v, $h, $P)
    {
        return (new Curve25519)->verify($v, $h, $P);
    }
    function curve25519_keygen($k)
    {
        return (new Curve25519)->keygen($k);
    }
}

?>

<?php
/*

    // shortcuts from standard curve25519
    private $zero = [0,0,0,0, 0,0,0,0, 0,0];
    private $one  = [1,0,0,0, 0,0,0,0, 0,0];
    private $nine = [9,0,0,0, 0,0,0,0, 0,0];
    function add($a, $b) {
        return [
            $a[0] + $b[0], $a[1] + $b[1], $a[2] + $b[2], $a[3] + $b[3], $a[4] + $b[4],
            $a[5] + $b[5], $a[6] + $b[6], $a[7] + $b[7], $a[8] + $b[8], $a[9] + $b[9]
        ];
    }
    function sub($a, $b) {
        $r = [
            ($c = 0x7ffffda + $a[0] - $b[0]             ) & 0x3ffffff,
            ($c = 0x3fffffe + $a[1] - $b[1] + ($c >> 26)) & 0x1ffffff,
            ($c = 0x7fffffe + $a[2] - $b[2] + ($c >> 25)) & 0x3ffffff,
            ($c = 0x3fffffe + $a[3] - $b[3] + ($c >> 26)) & 0x1ffffff,
            ($c = 0x7fffffe + $a[4] - $b[4] + ($c >> 25)) & 0x3ffffff,
            ($c = 0x3fffffe + $a[5] - $b[5] + ($c >> 26)) & 0x1ffffff,
            ($c = 0x7fffffe + $a[6] - $b[6] + ($c >> 25)) & 0x3ffffff,
            ($c = 0x3fffffe + $a[7] - $b[7] + ($c >> 26)) & 0x1ffffff,
            ($c = 0x7fffffe + $a[8] - $b[8] + ($c >> 25)) & 0x3ffffff,
            ($c = 0x3fffffe + $a[9] - $b[9] + ($c >> 26)) & 0x1ffffff,
        ];
        $r[0] += 19 * ($c >> 25);
        return $r;
    }
    function mul($a, $b) {
        list($s0, $s1, $s2, $s3, $s4, $s5, $s6, $s7, $s8, $s9) = $a;
        list($r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7, $r8, $r9) = $b;
        $r1_2 = $r1 * 2;
        $r3_2 = $r3 * 2;
        $r5_2 = $r5 * 2;
        $r2_19 = $r2 * 19;
        $r4_19 = $r4 * 19;
        $r5_19 = $r5 * 19;
        $r6_19 = $r6 * 19;
        $r7_19 = $r7 * 19;
        $r8_19 = $r8 * 19;
        $r9_19 = $r9 * 19;
        $r3_38 = $r3 * 38;
        $r5_38 = $r5 * 38;
        $r7_38 = $r7 * 38;
        $r9_38 = $r9 * 38;
        $r = [
            ($c = $m0 = ($r0 * $s0) + ($r1 * 38 * $s9) + ($r2_19 * $s8) + ($r3_38   * $s7) + ($r4_19 * $s6) + ($r5_38 * $s5) + ($r6_19 * $s4) + ($r7_38  * $s3) + ($r8_19 * $s2) + ($r9_38 * $s1)             ) & 0x3ffffff,
            ($c = $m1 = ($r0 * $s1) + ($r1      * $s0) + ($r2_19 * $s9) + ($r3 * 19 * $s8) + ($r4_19 * $s7) + ($r5_19 * $s6) + ($r6_19 * $s5) + ($r7_19  * $s4) + ($r8_19 * $s3) + ($r9_19 * $s2) + ($c >> 26)) & 0x1ffffff,
            ($c = $m2 = ($r0 * $s2) + ($r1_2    * $s1) + ($r2    * $s0) + ($r3_38   * $s9) + ($r4_19 * $s8) + ($r5_38 * $s7) + ($r6_19 * $s6) + ($r7_38  * $s5) + ($r8_19 * $s4) + ($r9_38 * $s3) + ($c >> 25)) & 0x3ffffff,
            ($c = $m3 = ($r0 * $s3) + ($r1      * $s2) + ($r2    * $s1) + ($r3      * $s0) + ($r4_19 * $s9) + ($r5_19 * $s8) + ($r6_19 * $s7) + ($r7_19  * $s6) + ($r8_19 * $s5) + ($r9_19 * $s4) + ($c >> 26)) & 0x1ffffff,
            ($c = $m4 = ($r0 * $s4) + ($r1_2    * $s3) + ($r2    * $s2) + ($r3_2    * $s1) + ($r4    * $s0) + ($r5_38 * $s9) + ($r6_19 * $s8) + ($r7_38  * $s7) + ($r8_19 * $s6) + ($r9_38 * $s5) + ($c >> 25)) & 0x3ffffff,
            ($c = $m5 = ($r0 * $s5) + ($r1      * $s4) + ($r2    * $s3) + ($r3      * $s2) + ($r4    * $s1) + ($r5    * $s0) + ($r6_19 * $s9) + ($r7_19  * $s8) + ($r8_19 * $s7) + ($r9_19 * $s6) + ($c >> 26)) & 0x1ffffff,
            ($c = $m6 = ($r0 * $s6) + ($r1_2    * $s5) + ($r2    * $s4) + ($r3_2    * $s3) + ($r4    * $s2) + ($r5_2  * $s1) + ($r6    * $s0) + ($r7_38  * $s9) + ($r8_19 * $s8) + ($r9_38 * $s7) + ($c >> 25)) & 0x3ffffff,
            ($c = $m7 = ($r0 * $s7) + ($r1      * $s6) + ($r2    * $s5) + ($r3      * $s4) + ($r4    * $s3) + ($r5    * $s2) + ($r6    * $s1) + ($r7     * $s0) + ($r8_19 * $s9) + ($r9_19 * $s8) + ($c >> 26)) & 0x1ffffff,
            ($c = $m8 = ($r0 * $s8) + ($r1_2    * $s7) + ($r2    * $s6) + ($r3_2    * $s5) + ($r4    * $s4) + ($r5_2  * $s3) + ($r6    * $s2) + ($r7 * 2 * $s1) + ($r8    * $s0) + ($r9_38 * $s9) + ($c >> 25)) & 0x3ffffff,
            ($c = $m9 = ($r0 * $s9) + ($r1      * $s8) + ($r2    * $s7) + ($r3      * $s6) + ($r4    * $s5) + ($r5    * $s4) + ($r6    * $s3) + ($r7     * $s2) + ($r8    * $s1) + ($r9    * $s0) + ($c >> 26)) & 0x1ffffff
        ];
        $r[0] += ($c = 19 * ($c >> 25)) & 0x3ffffff;
        $r[1] +=            ($c >> 26);
        return $r;
    }
    function sqr($a, $n = 1) {
        list($r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7, $r8, $r9) = $a;
        do {
            $r0_2 = $r0 * 2;
            $r1_2 = $r1 * 2;
            $r2_2 = $r2 * 2;
            $r3_2 = $r3 * 2;
            $r4_2 = $r4 * 2;
            $r5_2 = $r5 * 2;
            $r7_2 = $r7 * 2;
            $r6_19 = $r6 * 19;
            $r7_38 = $r7 * 38;
            $r8_19 = $r8 * 19;
            $r9_38 = $r9 * 38;
            $s0 = ($r0   * $r0) + ($r5 * $r5 * 38) + ($r6_19 * $r4_2) + ($r7_38 * $r3_2) + ($r8_19 * $r2_2) + ($r9_38 * $r1_2);
            $s1 = ($r0_2 * $r1)                    + ($r6_19 * $r5_2) + ($r7_38 * $r4  ) + ($r8_19 * $r3_2) + ($r9_38 * $r2  );
            $s2 = ($r0_2 * $r2) + ($r1_2 * $r1)    + ($r6_19 * $r6  ) + ($r7_38 * $r5_2) + ($r8_19 * $r4_2) + ($r9_38 * $r3_2);
            $s3 = ($r0_2 * $r3) + ($r1_2 * $r2)                       + ($r7_38 * $r6  ) + ($r8_19 * $r5_2) + ($r9_38 * $r4  );
            $s4 = ($r0_2 * $r4) + ($r1_2 * $r3_2) + ($r2   * $r2)     + ($r7_38 * $r7  ) + ($r8_19 * $r6*2) + ($r9_38 * $r5_2);
            $s5 = ($r0_2 * $r5) + ($r1_2 * $r4  ) + ($r2_2 * $r3)                        + ($r8_19 * $r7_2) + ($r9_38 * $r6  );
            $s6 = ($r0_2 * $r6) + ($r1_2 * $r5_2) + ($r2_2 * $r4) + ($r3_2 * $r3)        + ($r8_19 * $r8  ) + ($r9_38 * $r7_2);
            $s7 = ($r0_2 * $r7) + ($r1_2 * $r6  ) + ($r2_2 * $r5) + ($r3_2 * $r4  )                         + ($r9_38 * $r8  );
            $s8 = ($r0_2 * $r8) + ($r1_2 * $r7_2) + ($r2_2 * $r6) + ($r3_2 * $r5_2) + ($r4 * $r4  )         + ($r9_38 * $r9  );
            $s9 = ($r0_2 * $r9) + ($r1_2 * $r8  ) + ($r2_2 * $r7) + ($r3_2 * $r6  ) + ($r4 * $r5_2);
            $r0 = ($c = $s0             ) & 0x3ffffff;
            $r1 = ($c = $s1 + ($c >> 26)) & 0x1ffffff;
            $r2 = ($c = $s2 + ($c >> 25)) & 0x3ffffff;
            $r3 = ($c = $s3 + ($c >> 26)) & 0x1ffffff;
            $r4 = ($c = $s4 + ($c >> 25)) & 0x3ffffff;
            $r5 = ($c = $s5 + ($c >> 26)) & 0x1ffffff;
            $r6 = ($c = $s6 + ($c >> 25)) & 0x3ffffff;
            $r7 = ($c = $s7 + ($c >> 26)) & 0x1ffffff;
            $r8 = ($c = $s8 + ($c >> 25)) & 0x3ffffff;
            $r9 = ($c = $s9 + ($c >> 26)) & 0x1ffffff;
            $r0 += ($c = 19 * ($c >> 25)) & 0x3ffffff;
            $r1 +=            ($c >> 26);
        } while (--$n);
        return [$r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7, $r8, $r9];
    }
    function mul121665($in) {
        $r = [
            ($c = $in[0] * 121665             ) & 0x3ffffff,
            ($c = $in[1] * 121665 + ($c >> 26)) & 0x1ffffff,
            ($c = $in[2] * 121665 + ($c >> 25)) & 0x3ffffff,
            ($c = $in[3] * 121665 + ($c >> 26)) & 0x1ffffff,
            ($c = $in[4] * 121665 + ($c >> 25)) & 0x3ffffff,
            ($c = $in[5] * 121665 + ($c >> 26)) & 0x1ffffff,
            ($c = $in[6] * 121665 + ($c >> 25)) & 0x3ffffff,
            ($c = $in[7] * 121665 + ($c >> 26)) & 0x1ffffff,
            ($c = $in[8] * 121665 + ($c >> 25)) & 0x3ffffff,
            ($c = $in[9] * 121665 + ($c >> 26)) & 0x1ffffff,
        ];
        $r[0] += 19 * ($c >> 25);
        return $r;
    }
    function scalarmult($f, $c) {
        $t = $this->one;
        $u = $this->zero;
        $v = $this->one;
        $w = $c;
        $swapBit = 1;
        $i = 254;
        while ($i --> 2) {
            $x = $this->add($w, $v);
            $v = $this->sub($w, $v);
            $y = $this->add($t, $u);
            $u = $this->sub($t, $u);
            $t = $this->mul($y, $v);
            $u = $this->mul($x, $u);
            $z = $this->add($t, $u);
            $u = $this->sqr($this->sub($t, $u));
            $t = $this->sqr($z);
            $u = $this->mul($u, $c);
            $x = $this->sqr($x);
            $v = $this->sqr($v);
            $w = $this->mul($x, $v);
            $v = $this->sub($x, $v);
            $v = $this->mul($v, $this->add($this->mul121665($v), $x));
            $b = ($f[$i >> 3] >> ($i & 7)) & 1;
            $swap = $b ^ $swapBit;
            list($w, $t) = [[$w, $t], [$t, $w]][$swap];
            list($v, $u) = [[$v, $u], [$u, $v]][$swap];
            $swapBit = $b;
        }
        $i = 3;
        while ($i--) {
            $x = $this->sqr($this->add($w, $v));
            $v = $this->sqr($this->sub($w, $v));
            $w = $this->mul($x, $v);
            $v = $this->sub($x, $v);
            $v = $this->mul($v, $this->add($this->mul121665($v), $x));
        }
        $a = $this->sqr($v);
        $b = $this->mul($this->sqr($a, 2), $v);
        $a = $this->mul($b, $a);
        $b = $this->mul($this->sqr($a), $b);
        $b = $this->mul($this->sqr($b, 5), $b);
        $c = $this->mul($this->sqr($b, 10), $b);
        $b = $this->mul($this->sqr($this->mul($this->sqr($c, 20), $c), 10), $b);
        $c = $this->mul($this->sqr($b, 50), $b);
        $r = $this->mul($w, $this->mul($this->sqr($this->mul($this->sqr($this->mul($this->sqr($c, 100), $c), 50), $b), 5), $a));
        $r = [
            ($c = $r[0] + 0x4000000             ) & 0x3ffffff,
            ($c = $r[1] + 0x1ffffff + ($c >> 26)) & 0x1ffffff,
            ($c = $r[2] + 0x3ffffff + ($c >> 25)) & 0x3ffffff,
            ($c = $r[3] + 0x1ffffff + ($c >> 26)) & 0x1ffffff,
            ($c = $r[4] + 0x3ffffff + ($c >> 25)) & 0x3ffffff,
            ($c = $r[5] + 0x1ffffff + ($c >> 26)) & 0x1ffffff,
            ($c = $r[6] + 0x3ffffff + ($c >> 25)) & 0x3ffffff,
            ($c = $r[7] + 0x1ffffff + ($c >> 26)) & 0x1ffffff,
            ($c = $r[8] + 0x3ffffff + ($c >> 25)) & 0x3ffffff,
            ($c = $r[9] + 0x1ffffff + ($c >> 26)) & 0x1ffffff
        ];
        return pack('V8',
             $r[0]        | ($r[1] << 26),
            ($r[1] >>  6) | ($r[2] << 19),
            ($r[2] >> 13) | ($r[3] << 13),
            ($r[3] >> 19) | ($r[4] <<  6),
             $r[5]        | ($r[6] << 25),
            ($r[6] >>  7) | ($r[7] << 19),
            ($r[7] >> 13) | ($r[8] << 12),
            ($r[8] >> 20) | ($r[9] <<  6)
        );
    }
    function clamp($secret)
    {
        $e = array_values(unpack('C32', $secret));
        $e[0]  &= 0xf8;
        $e[31] &= 0x7f;
        $e[31] |= 0x40;
        return $e;
    }
    function getPublic($secret)
    {
        if (!is_string($secret) || strlen($secret) !== 32) {
            throw new InvalidArgumentException('Secret must be a 32 byte string');
        }
        return $this->scalarmult($this->clamp($secret), $this->nine);
    }
    function getShared($secret, $public)
    {
        if (!is_string($secret) || strlen($secret) !== 32) {
            throw new InvalidArgumentException('Secret must be a 32 byte string');
        }
        if (!is_string($public) || strlen($public) !== 32) {
            throw new InvalidArgumentException('Public must be a 32 byte string');
        }
        $w = unpack('V8', $public);
        $r = [
              $w[1]                         & 0x3ffffff, // 26
            (($w[1] >> 26) | ($w[2] <<  6)) & 0x1ffffff, // 25 - 51
            (($w[2] >> 19) | ($w[3] << 13)) & 0x3ffffff, // 26 - 77
            (($w[3] >> 13) | ($w[4] << 19)) & 0x1ffffff, // 25 - 102
             ($w[4] >>  6)                  & 0x3ffffff, // 26 - 128
              $w[5]                         & 0x1ffffff, // 25 - 153
            (($w[5] >> 25) | ($w[6] <<  7)) & 0x3ffffff, // 26 - 179
            (($w[6] >> 19) | ($w[7] << 13)) & 0x1ffffff, // 25 - 204
            (($w[7] >> 12) | ($w[8] << 20)) & 0x3ffffff, // 26 - 230
             ($w[8] >> 6)                   & 0x1ffffff, // 25 - 255
        ];
        return $this->scalarmult($this->clamp($secret), $r);
  
  }
*/
?>