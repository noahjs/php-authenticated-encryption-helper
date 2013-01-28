<?php

/*
 * Authenticated Encryption Helper
 * -------------------------------
 * For consistant implementation of Encrypt Then Mac using
 *  - Key Generation: PBKDF2
 *  - Encryption:     OpenSSL, AES CBC Random IV
 *  - Secure MAC:     HMAC sha256
 *  - PRG:            OpenSSL, "random_pseudo_bytes"
 * Requires:
 *  - OpenSSL
 *  - PHP 5.3+ (tested using 5.4)
 * Notes:
 *  - Plaintext Keys are 64 Bytes (char) / 512 bits
 *  - When Encrypted they are 224 Bytes (char), ie. DB Storage = VARCHAR(225)
 */





/*-----------------------------------------------------------
 * PBKDF2 Implementation (described in RFC 2898) from php.net
 *-----------------------------------------------------------
 * @param   string  p   password 
 * @param   string  s   salt 
 * @param   int     c   iteration count (use 1000 or higher) 
 * @param   int     kl  derived key length 
 * @param   string  a   hash algorithm 
 * @param   int     st  start position of result 
 *
 * @return  string  derived key 
 */
function hash_pbkdf2 ( $p, $s, $c, $kl, $a = 'sha256', $st=0 ) { 

  $kb  =  $st+$kl;     // Key blocks to compute 
  $dk  =  '';          // Derived key 

  // Create key 
  for ($block=1; $block<=$kb; $block++) {

    // Initial hash for this block 
    $ib = $h = hash_hmac($a, $s . pack('N', $block), $p, true); 

    // Perform block iterations 
    for ($i=1; $i<$c; $i++) { 
      // XOR each iterate 
      $ib  ^=  ($h = hash_hmac($a, $h, $p, true)); 
    } 

    $dk  .=  $ib;   // Append iterated block 

  } 

  // Return derived key of correct length 
  return substr($dk, $st, $kl); 

} 

/*-----------------------------------------------------------
 * RANDOM: Drop in replacement for mt_rand
 *-----------------------------------------------------------
 * @param   int  min   Low end of int being returned 
 * @param   int  max   High end of int being returned 
 *
 * @return  int  Random number btw Min and Max
 */  
function crypto_rand( $min, $max ) {
    
    // What is range of numbers
    $range  =  $max - $min;
    
    // Is range > 0
    if ($range == 0) return $min; // not so random...
    
    // get length in bytes
    $length  =  (int) (log($range,2) / 8) + 1;
    
    // Get random bytes
    $random_bytes  =  openssl_random_pseudo_bytes( $length, $s );

    // Convert to int Modulus Max number of the Rnage
    $num  =  hexdec( bin2hex( $random_bytes ) ) % $range;

    // Make sure we are within range
    return $num + $min;
}

/*-----------------------------------------------------------
 * GEN KEY: Generate a cryptography Key
 *-----------------------------------------------------------
 * 
 * Length must be LTE 79 char, when encrypted this is 224 char and fits in normal VARCHAR in DB
 *
 * @return  string  Crypto Key
 */  
function gen_crypto_key() {
    
    do{

      // Get random bytes
      $random_bytes   =  openssl_random_pseudo_bytes( 100, $was_secure );

    }while( ! $was_secure );

    // Make sure we are within range
    return sha256( $random_bytes ); // 64 bytes (chars)
}

/*-----------------------------------------------------------
 * ENCRYPT: AES 256 bit, CBC rand IV
 * ENCRYPT THEN MAC, Authenticated Encryption Helper
 *-----------------------------------------------------------
 * @param   string  base_key    Base Key that will be used to derive encryption Key
 * @param   string  data      Clear text that will be encrypted
 *
 * @return  string  Encrypted ciphertext
 */
function ssl_encrypt( $base_key, $data ){

  // Get the Randoms
  $salt  =  openssl_random_pseudo_bytes(8);
  $iv  =  openssl_random_pseudo_bytes(16);
  
  // Generate the KEY
  $key  =  hash_pbkdf2( $base_key, $salt, 1000, 64); // 64 = 512 bits

  // Create Clear text
  $clear_text  =  $data;

  // do encryption
  $ciphertext_raw  =  openssl_encrypt( $clear_text, "aes-256-cbc", $key, true, $iv );

  // Generate Hash of crypt text
  $hash  =  hash_hmac( "sha256", $ciphertext_raw, $key );

  // Encode everything
  $ciphertext  =  base64_encode( $iv.$salt.$hash.$ciphertext_raw );

  /*
    Ciphertext Components:  | IV [16] |  SALT [8] |  HASH( cipher_text ) [64]  |  CIPHER_TEXT ( data ) |
  */

  return $ciphertext;

}

/*-----------------------------------------------------------
 * DECRYPT: AES 256 bit, CBC rand IV
 * CRYPT THEN MAC, Authenticated Encryption Helper
 *-----------------------------------------------------------
 * @param   string  base_key       Base Key that will be used to derive encryption Key
 * @param   string  ciphertext_64  Base 64 encoded Ciphertext
 *
 * @return  string  FALSE or Cleartext
 */
function ssl_decrypt( $base_key, $ciphertext_64 ){

  /*
    Ciphertext Components:  | IV [16] |  SALT [8] |  HASH( cipher_text ) [64]  |  CIPHER_TEXT ( data ) |
  */

  // decode base 64
  $ciphertext  =  base64_decode( $ciphertext_64 );

  // get the IV
  $iv  =  substr( $ciphertext, 0, 16);
  
  // get the Salt
  $salt  =  substr( $ciphertext, 16, 8);
  
  // get the hash (last 64 char)
  $hash  =  substr( $ciphertext, 24, 64);      // Dont check right away, we want function to take same length of time on pass OR fail
  
  // get the ciphertext_raw
  $ciphertext_raw =  substr( $ciphertext, 88);

  // Generate the KEY
  $key  =  hash_pbkdf2( $base_key, $salt, 1000, 64); // 64 = 512 bits
  
  // do decryption
  $plaintext_raw  =  openssl_decrypt($ciphertext_raw, "aes-256-cbc", $key, true, $iv );

  // Create Clear text
  $clear_text  =  $plaintext_raw;
  
  // Generate hash hash ciphertext
  $gen_hash  =  hash_hmac( "sha256", $ciphertext_raw, $key );

  // Validate Hash is correct   AND   we got a proper decryption
  if ( ($hash == $gen_hash) AND ($plaintext_raw != "") ) {
    return $clear_text;
  }else{
    return false;
  } 


}


