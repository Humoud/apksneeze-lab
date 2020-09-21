

rule WebLinks
{
    meta:
        description = "detect web links"

    strings:
        $a1 = "http://" nocase ascii wide
        $a2 = "https://" nocase ascii wide
        $b1 = "schemas.android.com"
        $b2 = "github.com"
        $b3 = "google.com"

    condition:
        ($a1 or $a2) and not ($b1 or $b2 or $b3)
}

rule IP_Address
{
    meta:
        description = "detect IP addresses"
    strings:
        $re = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/

    condition:
        $re
}

rule Database
{
    meta:
        description = "detect database connections"
    strings:
        $a1 = "mysql" nocase ascii wide
        $a2 = "postgre" nocase ascii wide
        $b1 = "mongo" nocase ascii wide

    condition:
        any of them
}

rule SUSP_Base64_Encoded_Hex_Encoded_Code {
   meta:
      author = "Florian Roth"
      description = "Detects hex encoded code that has been base64 encoded"
      date = "2019-04-29"
      score = 65
      reference = "Internal Research"
   strings:
      $x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 }
      $x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e }
   condition:
      1 of them
}