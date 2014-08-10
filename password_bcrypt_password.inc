<?php

/**
 * @file
 * Secure bcrypt password hashing functions for user authentication.
 *
 * Based on bcrypt and the Portable PHP password hashing framework.
 * @see http://www.openwall.com/phpass/
 *      https://gist.github.com/1053158
 *
 * This is a custom version of Drupal's password hashing API.
 *
 * It contains enhanced replacements for:
 *   user_hash_password()
 *   user_check_password()
 *   user_needs_new_hash()
 */

/**
 * bCryptic by Jonathan K Mickelson <jkmickelson.com>
 * This code is released in the public domain.
 * (Enhanced from Bcrypt original by Marco Arment <me@marco.org>)
 *
 * Some alterations made by Dmitriy Novikov <dimmu.neivan@gmail.com>
 *
 * THERE IS ABSOLUTELY NO WARRANTY.
 *
 * Usage example:
 * // In a registration or password-change form:
 * $hash_for_user = bCryptic::hash($_POST['password']);
 *
 * // In a login form:
 * $is_correct = bCryptic::check($_POST['password'], $stored_hash_for_user);
 * // In a login form when migrating entries gradually from a legacy SHA-1 hash:
 * $is_correct = bCryptic::check(
 *     $_POST['password'],
 *     $stored_hash_for_user,
 *     function($password, $hash) { return $hash == sha1($password); }
 * );
 * if ($is_correct && bCryptic::legacy_hash_status($stored_hash_for_user)!==0) {
 *     $user->store_new_hash(bCryptic::hash($_POST['password']));
 * }
 */

class bCryptic {
    // the bcrypt algorithm declares a work factor range of 4-31.
    // (one may change the minimum and maximum factors to customize
    //  a smaller range within those values)
    const MINIMUM_WORK_FACTOR = 4;
    const MAXIMUM_WORK_FACTOR = 31;
    const DEFAULT_WORK_FACTOR = 10; // sysadmin/coder selectable

    public static function hash($password, $work_factor = 0) {
        if (version_compare(PHP_VERSION, '5.3') < 0) {
            throw new Exception('bCryptic requires PHP 5.3 or above');
        }

        $work_factor = self::get_work_boundary($work_factor);

        $salt =
            '$2y$' . str_pad($work_factor, 2, '0', STR_PAD_LEFT) . '$'
            . substr(
                // drupal_random_bytes() chooses the best available pseudo-random source.
                strtr(base64_encode(drupal_random_bytes(16)), '+', '.'),
                0, 22
            )
        ;
        return crypt($password, $salt);
    }

    public static function get_work_boundary($work_factor = 0) {
        if (!$work_factor) {
            $work_factor = self::DEFAULT_WORK_FACTOR;
        }
        if ($work_factor < self::MINIMUM_WORK_FACTOR) {
            $work_factor = self::MINIMUM_WORK_FACTOR;
        }
        elseif ($work_factor > self::MAXIMUM_WORK_FACTOR) {
            $work_factor = self::MAXIMUM_WORK_FACTOR;
        }
        return $work_factor;
    }

    public static function check($password, $stored_hash, $legacy_handler = NULL) {
        if (version_compare(PHP_VERSION, '5.3') < 0) {
            throw new Exception('bCryptic requires PHP 5.3 or above');
        }

        if (self::legacy_hash_status($stored_hash) > 0) {
            if ($legacy_handler) {
                return call_user_func($legacy_handler, $password, $stored_hash);
            }
            else {
                throw new Exception('Unsupported hash format');
            }
        }

        return (crypt($password, $stored_hash) == $stored_hash);
    }

    public static function legacy_hash_status($hash) {
        if (substr($hash, 0, 4) != '$2y$') {
            return 1; // not bcrypt
        }

        $stored_work_factor = substr($hash, 4, 2) * 1;
        if (!$stored_work_factor) {
            // this should not occur unless hash is corrupted
            return 2; // not valid bcrypt
        }

        if ($stored_work_factor != self::get_work_boundary($stored_work_factor)) {
            return -1; // signal that the bcrypt work_factor is currently out-of-bounds.
        }

        return 0;
    }
}





/**
 * The standard log2 number of iterations for password stretching. This should
 * increase by 1 every Drupal version in order to counteract increases in the
 * speed and power of computers available to crack the hashes.
 */
define('DRUPAL_HASH_COUNT', 15);

/**
 * The minimum allowed log2 number of iterations for password stretching.
 */
define('DRUPAL_MIN_HASH_COUNT', 7);

/**
 * The maximum allowed log2 number of iterations for password stretching.
 */
define('DRUPAL_MAX_HASH_COUNT', 30);

/**
 * The expected (and maximum) number of characters in a hashed password.
 */
define('DRUPAL_HASH_LENGTH', 55);

/**
 * Returns a string for mapping an int to the corresponding base 64 character.
 */
function _password_itoa64() {
  return './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
}

/**
 * Encode bytes into printable base 64 using the *nix standard from crypt().
 *
 * @param $input
 *   The string containing bytes to encode.
 * @param $count
 *   The number of characters (bytes) to encode.
 *
 * @return
 *   Encoded string
 */
function _password_base64_encode($input, $count) {
  $output = '';
  $i = 0;
  $itoa64 = _password_itoa64();
  do {
    $value = ord($input[$i++]);
    $output .= $itoa64[$value & 0x3f];
    if ($i < $count) {
      $value |= ord($input[$i]) << 8;
    }
    $output .= $itoa64[($value >> 6) & 0x3f];
    if ($i++ >= $count) {
      break;
    }
    if ($i < $count) {
      $value |= ord($input[$i]) << 16;
    }
    $output .= $itoa64[($value >> 12) & 0x3f];
    if ($i++ >= $count) {
      break;
    }
    $output .= $itoa64[($value >> 18) & 0x3f];
  } while ($i < $count);

  return $output;
}

/**
 * Generates a random base 64-encoded salt prefixed with settings for the hash.
 *
 * Proper use of salts may defeat a number of attacks, including:
 *  - The ability to try candidate passwords against multiple hashes at once.
 *  - The ability to use pre-hashed lists of candidate passwords.
 *  - The ability to determine whether two users have the same (or different)
 *    password without actually having to guess one of the passwords.
 *
 * @param $count_log2
 *   Integer that determines the number of iterations used in the hashing
 *   process. A larger value is more secure, but takes more time to complete.
 *
 * @return
 *   A 12 character string containing the iteration count and a random salt.
 */
function _password_generate_salt($count_log2) {
  $output = '$S$';
  // Ensure that $count_log2 is within set bounds.
  $count_log2 = _password_enforce_log2_boundaries($count_log2);
  // We encode the final log2 iteration count in base 64.
  $itoa64 = _password_itoa64();
  $output .= $itoa64[$count_log2];
  // 6 bytes is the standard salt for a portable phpass hash.
  $output .= _password_base64_encode(drupal_random_bytes(6), 6);
  return $output;
}

/**
 * Ensures that $count_log2 is within set bounds.
 *
 * @param $count_log2
 *   Integer that determines the number of iterations used in the hashing
 *   process. A larger value is more secure, but takes more time to complete.
 *
 * @return
 *   Integer within set bounds that is closest to $count_log2.
 */
function _password_enforce_log2_boundaries($count_log2) {
  if ($count_log2 < DRUPAL_MIN_HASH_COUNT) {
    return DRUPAL_MIN_HASH_COUNT;
  }
  elseif ($count_log2 > DRUPAL_MAX_HASH_COUNT) {
    return DRUPAL_MAX_HASH_COUNT;
  }

  return (int) $count_log2;
}

/**
 * Hash a password using a secure stretched hash.
 *
 * By using a salt and repeated hashing the password is "stretched". Its
 * security is increased because it becomes much more computationally costly
 * for an attacker to try to break the hash by brute-force computation of the
 * hashes of a large number of plain-text words or strings to find a match.
 *
 * @param $algo
 *   The string name of a hashing algorithm usable by hash(), like 'sha256'.
 * @param $password
 *   The plain-text password to hash.
 * @param $setting
 *   An existing hash or the output of _password_generate_salt().  Must be
 *   at least 12 characters (the settings and salt).
 *
 * @return
 *   A string containing the hashed password (and salt) or FALSE on failure.
 *   The return string will be truncated at DRUPAL_HASH_LENGTH characters max.
 */
function _password_crypt($algo, $password, $setting) {
  // The first 12 characters of an existing hash are its setting string.
  $setting = substr($setting, 0, 12);

  if ($setting[0] != '$' || $setting[2] != '$') {
    return FALSE;
  }
  $count_log2 = _password_get_count_log2($setting);
  // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
  if ($count_log2 < DRUPAL_MIN_HASH_COUNT || $count_log2 > DRUPAL_MAX_HASH_COUNT) {
    return FALSE;
  }
  $salt = substr($setting, 4, 8);
  // Hashes must have an 8 character salt.
  if (strlen($salt) != 8) {
    return FALSE;
  }

  // Convert the base 2 logarithm into an integer.
  $count = 1 << $count_log2;

  // We rely on the hash() function being available in PHP 5.2+.
  $hash = hash($algo, $salt . $password, TRUE);
  do {
    $hash = hash($algo, $hash . $password, TRUE);
  } while (--$count);

  $len = strlen($hash);
  $output =  $setting . _password_base64_encode($hash, $len);
  // _password_base64_encode() of a 16 byte MD5 will always be 22 characters.
  // _password_base64_encode() of a 64 byte sha512 will always be 86 characters.
  $expected = 12 + ceil((8 * $len) / 6);
  return (strlen($output) == $expected) ? substr($output, 0, DRUPAL_HASH_LENGTH) : FALSE;
}

/**
 * Parse the log2 iteration count from a stored hash or setting string.
 */
function _password_get_count_log2($setting) {
  $itoa64 = _password_itoa64();
  return strpos($itoa64, $setting[3]);
}

/**
 * Hash a password using a secure hash.
 *
 * @param $password
 *   A plain-text password.
 * @param $count_log2
 *   Ignored integer to specify the iteration count. Was used only during
 *   mass operations where a value less than the default is needed for speed.
 *
 * @return
 *   A string containing the hashed password (and a salt), or FALSE on failure.
 */
function user_hash_password($password, $count_log2 = 0) {
  return bCryptic::hash($password);
}

/**
 * Check whether a plain text password matches a stored hashed password.
 *
 * Alternative implementations of this function may use other data in the
 * $account object, for example the uid to look up the hash in a custom table
 * or remote database.
 *
 * @param $password
 *   A plain-text password
 * @param $account
 *   A user object with at least the fields from the {users} table.
 *
 * @return
 *   TRUE or FALSE.
 */
function user_check_password($password, $account) {
  if (substr($account->pass, 0, 2) == 'U$') {
    // This may be an updated password from user_update_7000(). Such hashes
    // have 'U' added as the first character and need an extra md5().
    $stored_hash = substr($account->pass, 1);
    $password = md5($password);
  }
  else {
    $stored_hash = $account->pass;
  }

  $type4 = substr($stored_hash, 0, 4);
  switch ($type4) {
    case '$2y$':
      return bCryptic::check($password, $stored_hash);
  }

  $type3 = substr($stored_hash, 0, 3);
  switch ($type3) {
    case '$S$':
      // A normal Drupal 7 password using sha512.
      $hash = _password_crypt('sha512', $password, $stored_hash);
      break;
    case '$H$':
      // phpBB3 uses "$H$" for the same thing as "$P$".
    case '$P$':
      // A phpass password generated using md5.  This is an
      // imported password or from an earlier Drupal version.
      $hash = _password_crypt('md5', $password, $stored_hash);
      break;
    default:
      return FALSE;
  }
  return ($hash && $stored_hash == $hash);
}

/**
 * Check whether a user's hashed password needs to be replaced with a new hash.
 *
 * This is typically called during the login process when the plain text
 * password is available. A new hash is needed when the desired work_force
 * boundary has changed or a different hash was originally used.
 *
 * @param $account
 *   A user object with at least the fields from the {users} table.
 *
 * @return
 *   TRUE or FALSE.
 */
function user_needs_new_hash($account) {
  // It may be a legacy hash or the bcrypt work force may be out-of-bounds
  if (bCryptic::legacy_hash_status($account->pass) !== 0) {
    return TRUE;
  }
  return FALSE;
}
