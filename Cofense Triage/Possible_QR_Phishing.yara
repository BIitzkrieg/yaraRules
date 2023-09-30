rule qr_phish {
meta:
  time_to_live="Forever"
  rule_context="Phishing Tactic"
  description="This rule looks for strings found in potential QR code based phishing emails."
strings: 
  $s1="scan" nocase
  $s2="QR code" nocase
  $s3="camera" nocase
  $s4="phone" nocase
  $s5="smartphone" nocase
condition:
  uint16(0) == 0x6552  and ($s1 and $s2) and ($s3 or $s4 or $s5)
}
