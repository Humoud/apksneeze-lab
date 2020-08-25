

rule WebLinks
{
    meta:
        description = "A test rule for the project - web links"

    strings:
        $a1 = "http://" nocase ascii wide
        $a2 = "https://" nocase ascii wide
        $b1 = "schemas.android.com"
        $b2 = "github.com"
        $b3 = "google.com"

    condition:
        ($a1 or $a2) and not ($b1 or $b2 or $b3)
}
