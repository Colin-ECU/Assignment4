// detect common properties of the BE2 and BE3 loader
rule BlackEnergy
{
    strings: 
        $hc1 = {68 97 04 81 1D 6A 01}
        $hc2 = {68 A8 06 B0 3B 6A 02}
        $hc3 = {68 14 06 F5 33 6A 01}
        $hc4 = {68 AF 02 91 AB 6A 01}
        $hc5 = {68 8A 86 39 56 6A 02}
        $hc6 = {68 19 2B 90 95 6A 01}
        $hc7 = {(68 | B?) 11 05 90 23}
        $hc8 = {(68 | B?) EB 05 4A 2F}
        $hc9 = {(68 | B?) B7 05 57 2A}
    condition:
        2 of ($hc*)
}

// detect BE3 variants that are not caught by the general BlackEnergy rule
rule BlackEnergy3
{
    strings: 
        $a1 = "MCSF_Config" ascii
        $a2 = "NTUSER.LOG" ascii
        $a3 = "ldplg" ascii
        $a4 = "unlplg" ascii
        $a5 = "getp" ascii
        $a6 = "getpd" ascii
        $a7 = "CSTR" ascii
        $a8 = "FONTCACHE.DAT" ascii
    condition:
        4 of them
}

// detect both packed and unpacked variants of the BE2 driver
rule BlackEnergy2_Driver
{
    strings:
        $a1 = {7E 4B 54 1A}
        $a2 = {E0 3C 96 A2}
        $a3 = "IofCompleteRequest" ascii
        $b1 = {31 A1 44 BC}
        $b2 = "IoAttachDeviceToDeviceStack" ascii
        $b3 = "KeInsertQueueDpc" ascii
        $c1 = {A3 41 FD 66}
        $c2 = {61 1E 4E F8}
        $c3 = "PsCreateSystemThread" ascii
    condition:
        all of ($a*) and 3 of ($b*, $c*)
}

// detect BE2 variants, typically plugins or loaders containing plugins
rule BlackEnergy2
{
    strings:
        $ex1 = "DispatchCommand" ascii
        $ex2 = "DispatchEvent" ascii
        $a1 = {68 A1 B0 5C 72}
        $a2 = {68 6B 43 59 4E}
        $a3 = {68 E6 4B 59 4E}
    condition:
        all of ($ex*) and 3 of ($a*)
}
