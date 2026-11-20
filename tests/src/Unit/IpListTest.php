<?php

namespace Drupal\Tests\diffy_trusted_login\Unit;

use Drupal\diffy_trusted_login\IpList;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests IP address and CIDR list parsing and validation.
 *
 * @group diffy_trusted_login
 */
#[CoversClass(IpList::class)]
#[Group('diffy_trusted_login')]
class IpListTest extends UnitTestCase {

  /**
   * Tests validation of single entries.
   *
   * @dataProvider providerIsValid
   */
  #[DataProvider('providerIsValid')]
  public function testIsValid(string $value, bool $expected): void {
    $this->assertSame($expected, IpList::isValid($value));
  }

  /**
   * Data provider for testIsValid().
   */
  public static function providerIsValid(): array {
    return [
      'IPv4' => ['203.0.113.10', TRUE],
      'IPv4 CIDR' => ['10.0.0.0/8', TRUE],
      'IPv4 /32' => ['203.0.113.10/32', TRUE],
      'IPv4 /0' => ['0.0.0.0/0', TRUE],
      'IPv6' => ['2001:db8::1', TRUE],
      'IPv6 CIDR' => ['2001:db8::/32', TRUE],
      'IPv6 loopback /128' => ['::1/128', TRUE],
      'IPv4 mask too large' => ['1.2.3.4/33', FALSE],
      'IPv6 mask too large' => ['2001:db8::/129', FALSE],
      'empty mask' => ['10.0.0.0/', FALSE],
      'negative mask' => ['10.0.0.0/-1', FALSE],
      'non-numeric mask' => ['10.0.0.0/abc', FALSE],
      'incomplete IPv4' => ['1.2.3/24', FALSE],
      'out-of-range octet' => ['256.1.1.1', FALSE],
      'hostname' => ['example.com', FALSE],
      'word' => ['foo', FALSE],
      'empty' => ['', FALSE],
    ];
  }

  /**
   * Tests splitting textarea input into entries.
   *
   * @dataProvider providerParse
   */
  #[DataProvider('providerParse')]
  public function testParse(string $input, array $expected): void {
    $this->assertSame($expected, IpList::parse($input));
  }

  /**
   * Data provider for testParse().
   */
  public static function providerParse(): array {
    return [
      'empty' => ['', []],
      'whitespace only' => ["  \n\t\n", []],
      'single' => ['1.2.3.4', ['1.2.3.4']],
      'trimmed, blank lines dropped' => ["  1.2.3.4 \n\n 10.0.0.0/8\n", ['1.2.3.4', '10.0.0.0/8']],
      'windows line endings' => ["1.2.3.4\r\n::1", ['1.2.3.4', '::1']],
      'duplicates removed, order kept' => ["::1\n1.2.3.4\n::1", ['::1', '1.2.3.4']],
    ];
  }

}
