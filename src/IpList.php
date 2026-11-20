<?php

namespace Drupal\diffy_trusted_login;

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Parses and validates lists of IP addresses and CIDR ranges.
 */
final class IpList {

  /**
   * Splits multi-line input into unique, trimmed, non-empty entries.
   *
   * @return string[]
   *   The entries, in input order.
   */
  public static function parse(string $value): array {
    return array_values(array_unique(array_filter(array_map('trim', preg_split('/\R/', $value)))));
  }

  /**
   * Whether a value is a valid IPv4/IPv6 address or CIDR range.
   */
  public static function isValid(string $value): bool {
    [$address, $mask] = array_pad(explode('/', $value, 2), 2, NULL);
    if (!filter_var($address, FILTER_VALIDATE_IP)) {
      return FALSE;
    }
    if ($mask === NULL) {
      return TRUE;
    }
    $max = str_contains($address, ':') ? 128 : 32;
    return ctype_digit($mask) && (int) $mask <= $max
      // Confirms Symfony, which does the matching, accepts the range too.
      && IpUtils::checkIp($address, $value);
  }

}
