rule SuspiciousStrings
{
    strings:
        $a = "malware"
        $b = "trojan"
        $c = "keylogger"

    condition:
        any of them
}
