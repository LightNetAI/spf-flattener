<?php
/**
 * IP range utilities.
 *
 * Reproduces the behaviour cfspflat relies on from netaddr's IPSet:
 *  - parse addresses and CIDR networks
 *  - merge overlapping and adjacent ranges
 *  - collapse to the minimal set of CIDRs (iter_cidrs)
 *
 * Arithmetic is done on integers via GMP when available, falling back to
 * bcmath, so IPv6 is handled exactly rather than through floats.
 */

require_once __DIR__ . '/Security.php';

class IPUtil {

    /** @var bool */
    private static $useGmp = null;

    /* ========================================================
     * Integer helpers
     * ====================================================== */

    private static function hasGmp() {
        if (self::$useGmp === null) {
            self::$useGmp = extension_loaded('gmp') && function_exists('gmp_add');
        }
        return self::$useGmp;
    }

    /** Decimal string -> internal integer */
    private static function i($dec) {
        return self::hasGmp() ? gmp_init((string) $dec, 10) : (string) $dec;
    }

    private static function add($a, $b) {
        return self::hasGmp() ? gmp_add($a, $b) : bcadd((string) $a, (string) $b, 0);
    }

    /** a - b, clamped at zero */
    private static function sub($a, $b) {
        if (self::hasGmp()) {
            $r = gmp_sub($a, $b);
            return gmp_sign($r) < 0 ? gmp_init(0, 10) : $r;
        }
        $r = bcsub((string) $a, (string) $b, 0);
        return bccomp($r, '0', 0) < 0 ? '0' : $r;
    }

    private static function cmp($a, $b) {
        return self::hasGmp() ? gmp_cmp($a, $b) : bccomp((string) $a, (string) $b, 0);
    }

    private static function pow2($n) {
        if (self::hasGmp()) {
            return gmp_pow(gmp_init(2, 10), (int) $n);
        }
        return bcpow('2', (string) (int) $n, 0);
    }

    private static function dec($a) {
        return self::hasGmp() ? gmp_strval($a, 10) : (string) $a;
    }

    /** Number of significant bits for an address family */
    private static function bitLength($version) {
        return $version === '4' ? 32 : 128;
    }

    private static function maxAddr($version) {
        return self::sub(self::pow2(self::bitLength($version)), 1);
    }

    /* ========================================================
     * Conversion
     * ====================================================== */

    /**
     * Convert a dotted-quad / colon-hex address to a decimal integer.
     *
     * @return string|null
     */
    public static function ipToInt($ip, $version) {
        if ($version === '4') {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                return null;
            }
            $parts = array_map('intval', explode('.', $ip));
            // 256^3 .. 256^0 without floating point issues (all fit in int)
            return (string) ($parts[0] * 16777216 + $parts[1] * 65536 + $parts[2] * 256 + $parts[3]);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            return null;
        }
        $bin = inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        $dec = '0';
        for ($i = 0; $i < 16; $i++) {
            $dec = self::add(self::mulSmall($dec, 256), (string) ord($bin[$i]));
        }
        return self::dec($dec);
    }

    private static function mulSmall($a, $n) {
        if (self::hasGmp()) {
            return gmp_mul($a, $n);
        }
        return bcmul((string) $a, (string) $n, 0);
    }

    /**
     * Convert a decimal integer back to a presentation address.
     */
    public static function intToIp($int, $version) {
        if ($version === '4') {
            $n = (int) self::dec($int);
            return long2ip($n);
        }

        $bin = '';
        $v = $int;
        for ($i = 0; $i < 16; $i++) {
            $byte = self::modSmall($v, 256);
            $bin = chr((int) self::dec($byte)) . $bin;
            $v = self::divSmall($v, 256);
        }
        return inet_ntop($bin);
    }

    private static function modSmall($a, $n) {
        if (self::hasGmp()) {
            return gmp_mod($a, $n);
        }
        return bcmod((string) $a, (string) $n);
    }

    private static function divSmall($a, $n) {
        if (self::hasGmp()) {
            return gmp_div_q($a, $n);
        }
        return bcdiv((string) $a, (string) $n, 0);
    }

    /* ========================================================
     * Parsing
     * ====================================================== */

    /**
     * Parse "1.2.3.4", "1.2.3.0/24", "2001:db8::/32" or "2001:db8::1".
     *
     * @return array{version:string,start:mixed,end:mixed}|null
     */
    public static function parseRange($token) {
        $token = trim($token);
        if ($token === '') {
            return null;
        }

        $bits = null;
        if (strpos($token, '/') !== false) {
            [$token, $bits] = explode('/', $token, 2);
            if (!ctype_digit((string) $bits)) {
                return null;
            }
            $bits = (int) $bits;
        }

        $version = (strpos($token, ':') !== false) ? '6' : '4';
        $maxBits = self::bitLength($version);

        $addrInt = self::ipToInt($token, $version);
        if ($addrInt === null) {
            return null;
        }

        if ($bits === null) {
            return ['version' => $version, 'start' => self::i($addrInt), 'end' => self::i($addrInt)];
        }

        if ($bits < 0 || $bits > $maxBits) {
            return null;
        }

        // Mask off the host bits: start = addr & mask, end = start | ~mask
        $hostBits = $maxBits - $bits;
        if ($hostBits > 0) {
            $size  = self::pow2($hostBits);
            $start = self::mulSmall(self::divSmall(self::i($addrInt), $size), $size);
            $end   = self::sub(self::add($start, $size), 1);
        } else {
            $start = self::i($addrInt);
            $end   = self::i($addrInt);
        }

        return ['version' => $version, 'start' => $start, 'end' => $end];
    }

    /**
     * Parse a list of tokens, ignoring anything unintelligible.
     *
     * Non-IP entries (e.g. bare include targets that could not be resolved)
     * are returned separately so the caller can preserve them.
     *
     * @return array{ranges:array,other:array}
     */
    public static function parseList(array $tokens) {
        $ranges = [];
        $other  = [];

        foreach ($tokens as $token) {
            $token = trim((string) $token);
            if ($token === '') {
                continue;
            }
            $range = self::parseRange($token);
            if ($range === null) {
                $other[] = $token;
            } else {
                $ranges[] = $range;
            }
        }

        return ['ranges' => $ranges, 'other' => $other];
    }

    /* ========================================================
     * Aggregation
     * ====================================================== */

    /**
     * Merge overlapping and adjacent ranges, per family.
     *
     * @param array $ranges From parseRange()
     * @return array Merged ranges, IPv4 first then IPv6, each ascending
     */
    public static function merge(array $ranges) {
        $byFamily = ['4' => [], '6' => []];

        foreach ($ranges as $r) {
            $byFamily[$r['version']][] = $r;
        }

        $merged = [];
        foreach (['4', '6'] as $version) {
            $list = $byFamily[$version];
            if (empty($list)) {
                continue;
            }

            usort($list, function ($a, $b) {
                $c = self::cmp($a['start'], $b['start']);
                return $c !== 0 ? $c : self::cmp($a['end'], $b['end']);
            });

            $current = null;
            foreach ($list as $r) {
                if ($current === null) {
                    $current = $r;
                    continue;
                }
                // Adjacent or overlapping: next.start <= current.end + 1
                $limit = self::add($current['end'], 1);
                if (self::cmp($r['start'], $limit) <= 0) {
                    if (self::cmp($r['end'], $current['end']) > 0) {
                        $current['end'] = $r['end'];
                    }
                } else {
                    $merged[] = $current;
                    $current = $r;
                }
            }
            if ($current !== null) {
                $merged[] = $current;
            }
        }

        return $merged;
    }

    /**
     * Split a merged range into the minimal set of aligned CIDRs.
     *
     * Mirrors netaddr's IPSet.iter_cidrs().
     *
     * @return array List of ['version' => '4'|'6', 'cidr' => 'x/y']
     */
    public static function rangeToCidrs($range) {
        $version  = $range['version'];
        $maxBits  = self::bitLength($version);
        $start    = $range['start'];
        $end      = $range['end'];
        $out      = [];

        while (self::cmp($start, $end) <= 0) {
            // Largest block we can start here: alignment of $start
            $blockBits = self::trailingZeros($start);
            if ($blockBits > $maxBits) {
                $blockBits = $maxBits;
            }

            // Shrink until the block fits inside the remaining range.
            while (true) {
                $size = self::pow2($blockBits);
                $blockEnd = self::sub(self::add($start, $size), 1);
                if (self::cmp($blockEnd, $end) <= 0 && $blockBits <= $maxBits) {
                    break;
                }
                $blockBits--;
                if ($blockBits < 0) {
                    break;
                }
            }

            $size = self::pow2($blockBits);
            $prefix = $maxBits - $blockBits;
            $out[] = [
                'version' => $version,
                'cidr'    => self::intToIp($start, $version) . '/' . $prefix,
            ];

            $start = self::add($start, $size);
        }

        return $out;
    }

    /**
     * How many trailing zero bits does this integer have?
     * Used to find the largest naturally aligned block at an address.
     */
    private static function trailingZeros($value) {
        $v = $value;
        $count = 0;
        $zero = self::i('0');

        // Zero divides by two indefinitely; the caller caps this at the
        // address width (32 or 128), which yields the correct /0 block.
        if (self::cmp($v, $zero) === 0) {
            return 128;
        }

        while (self::cmp($v, $zero) > 0) {
            // Continue while the low bit is 0; stop at the first set bit.
            if (self::cmp(self::modSmall($v, 2), $zero) !== 0) {
                break;
            }
            $v = self::divSmall($v, 2);
            $count++;
            if ($count > 128) {
                break;
            }
        }
        return $count;
    }

    /**
     * The full pipeline: tokens -> minimal SPF ip4:/ip6: tokens.
     *
     * @param array $tokens Addresses, networks, or arbitrary strings
     * @return array{sPF:array,other:array} sPF tokens plus unroutable entries
     */
    public static function collapse(array $tokens) {
        $parsed = self::parseList($tokens);
        $merged = self::merge($parsed['ranges']);

        $spf = [];
        foreach ($merged as $range) {
            foreach (self::rangeToCidrs($range) as $cidr) {
                $spf[] = ($cidr['version'] === '6' ? 'ip6:' : 'ip4:') . $cidr['cidr'];
            }
        }

        return ['spf' => $spf, 'other' => $parsed['other']];
    }
}
