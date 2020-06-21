// YARA 3.6.0 or higher is required to use this signature
import "pe"

private global rule coi_is_pe {
    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550
}

rule coi_backdoor 
{
    meta:
        description = "Detect CRASHOVERRIDE/Industroyer backdoors"
		author = "NCCIC ICS-CERT"

    strings:
        $co0 = {6a 43 ff 15}
        $co1 = {50 57 57 6a 2e 57 ff 15 ?? ?? ?? 00}
        $co2 = {5? 5? 5? 5? 5? 5? FF ?? ?? 6a ff 6a ff 6a ff 5? ff 15 ?? ?? ?? 00}

        $st1 = {4f 62 74 61 69 6e 55 73 65 72 41 67 65 6e 74 53 74 72 69 6e 67 00}
        $st2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.1)" wide fullword

    condition:
        filesize < 1MB and all of them
}

rule coi_dos
{
    meta:
        description = "Detect CRASHOVERRIDE/Industroyer DoS modules"
		author = "NCCIC ICS-CERT"

    strings:
        $p1 = {6a 02 6a 02 ff 15}
        $p2 = {5? 6a 00 6a 12 68 [4] 5? ff 15 [4] 50 68 [4] e8 ?? ?? FF FF 83 c4 08}

        $s0 = "WS2_32.dll" ascii nocase fullword
        $s1 = "point" ascii fullword

    condition:
        filesize < 500KB and all of them
}

rule coi_opc
{
    meta:
        description = "Detect CRASHOVERRIDE/Industroyer OPC modules"
		author = "NCCIC ICS-CERT"

    strings:
        $iid0 = {4F 3A C1 39 1E 01 D0 11 96 75 00 20 AF D8 AD B3}
        $iid1 = {54 3A C1 39 1E 01 D0 11 96 75 00 20 AF D8 AD B3}

        $co0 = {6a 00 6a 00 6a 00 6a 03 6a 01 6a 00 6a 00 6a ff 6a 00 ff 15}
        $co1 = {c7 45 ?? 00 00 00 00 c7 45 ?? 00 00 00 00 c7 45 ?? 00 00 00 00 c7 45 ?? 01 00 00 00 e8 ?? ?? ?? ff}

        $str0 = {63 74 6c 53 65 6c 4f 6e 00}
        $str1 = {73 74 56 61 6c 00}

    condition:
        filesize < 1MB and 1 of ($co*) and all of ($iid*,$str*)
}

rule coi_61850
{
    meta:
        description = "Detect CRASHOVERRIDE/Industroyer 61850 modules"
		author = "NCCIC ICS-CERT"

    strings:
        $hcp0 = {03 00 00 16 11 e0 00 00 00 01 00 c1 02 00 00 c2 02 00 01 c0 01 0a 00 00}
        $hcp1 = {03 00 00 24 02 f0 80 01 00 01 00 61 17 30 15 02 01 03 a0 10 a0 0e 02 01 01 a1 09 a0 03 80 01 09 a1 02 80 00}

        $iat0 = {47 65 74 41 64 61 70 74 65 72 73 49 6e 66 6f 00}

        $st0 = {73 74 56 61 6c 00}
        $st1 = {31 30 32 00}

    condition:
        filesize < 1MB and all of them
}

rule coi_notepad_heur
{
    meta:
        description = "Heuristics to try to identify the CRASHOVERRIDE/Industroyer alternate backdoor (trojanized notepad)."
		author = "NCCIC ICS-CERT"

    strings:
        $s0 = "Software\\Microsoft\\Notepad" wide fullword
        $s1 = "notepad.chm" ascii fullword
        $s2 = "CLSID\\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\\InprocServer32" ascii fullword

        $c0 = {F3 A4}
        $c1 = {60 9c}
        $c2 = {33 f0}
        $c3 = {83 e? 04 0f 85 ?? ?? ff ff}

    condition:
        filesize < 500KB and all of them and #c2 >= 10
}

rule coi_104
{
    meta:
        description = "Detect CRASHOVERRIDE/Industroyer IEC 104 modules"
		author = "NCCIC ICS-CERT"

    strings:
        $co0 = {2E 2E 00 00 68 0E 00 00 00 00 64 01 06 00 01 00 00 00 00 14}
        $co1 = {c6 ?? 2d 8b 46 04 c6 ?? 01 01 8b 46 04 c6 ?? 02 06 8b 46 04 c6 ?? 03 00}
        $co2 = {c7 ?? [4] c7 ?? 04 68 04 03 00 c7 ?? 08 00 00 00 00 c7 ?? 0c 00 00 00 00}
        $co3 = {80 78 04 68}

    condition:
        filesize < 1MB and all of them
}

rule coi_launcher
{
    meta:
        description = "Detect CRASHOVERRIDE/Industroyer launchers"
		author = "NCCIC ICS-CERT"

    strings:
        $co0 = {6A 00 6A 00 6A 00 68 ?? ?? ?? 00 6A 00 6A 00 FF 15}
        $co1 = {6a 01 6a 00 6a 00 6a 00}
        $co2 = {6a 00 6a 01 6a 00 ff 15 ?? ?? ?? 00}
        
        $st0 = {68 00 61 00 73 00 6c 00 6f 00}
        $st1 = "Crash" ascii fullword

    condition:
        filesize < 1MB and all of them
}

rule coi_wiper
{
    meta:
        description = "Detect CRASHOVERRIDE/Industroyer wiper modules"
		author = "NCCIC ICS-CERT"

    strings:
        $st1 = "SYS_BASCON.COM" wide nocase fullword
        $st2 = {43 72 61 73 68 00}

        $co0 = {6a 02 68 [4] 6a 02 5? 68 [4] ff b5 [4] ff 15}
        $co1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 02}
        $co2 = {0f 1f 84 00 00 00 00 00}
        $co3 = {5? 6a 00 6a 01 ff 15 [4] [1-2] 6a 01 5? ff 15}

    condition:
        filesize < 1MB and all of them
}

rule coi_port_scanner_heur
{
    meta:
        description = "Heuristics to detect packed and unpacked versions of the custom port scanner"
		author = "NCCIC ICS-CERT"

    strings:
        $st = "SystemFunction036" ascii fullword

        $unp0 = "^(.+?.exe).*\\s+-ip\\s*=\\s*(.+)\\s+-ports\\s*=\\s*(.+)$" wide fullword
        $unp1 = {d1 e8 49 3d ff 7f 00 00}
        $unp2 = {ff 15 ?? ?? ?? 00 b9 45 27 00 00 3b c1 7f 45}

        $pk0 = "UPX0"
        $pk1 = {4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 44 56 41 50 49 33 32 2E 64 6C 6C 00 57 53 32 5F 33 32 2E 64 6C 6C 00 00}
        $pk2 = {56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 53 79 73 74 65 6D 46 75 6E 63 74 69 6F 6E 30 33 36 00 00 40 06 00 18 00}
        
    condition:
        filesize < 1MB and $st and (all of ($unp*) or all of ($pk*))
}

rule coi_cred_dump_heur
{
    meta:
        description = "Heuristics to detect packed and unpacked versions of the credential dumper"
		author = "NCCIC ICS-CERT"

    strings:
        $st0 = "UPX0" ascii fullword
        $st1 = "SCardConnectW" ascii fullword
        $st2 = "DsGetDcNameW" ascii fullword
        $st3 = "CopySid" ascii fullword
        $st4 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 2000 > Nul & Del \"%s\"" wide fullword
        $st5 = "036" ascii

        $iat0 = {00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 44 56 41 50 49 33 32 2E 64 6C 6C 00 43 52 59 50 54 33 32 2E 64 6C 6C 00 63 72 79 70 74 64 6C 6C 2E 64 6C 6C 00}
        $iat1 = {45 78 69 74 50 72 6F 63 65 73 73 00 00 00 43 6F 70 79 53 69 64 00 00 00 43 65 72 74 4F 70 65 6E 53 74 6F 72 65 00 00 00 4D 44 35 49 6E 69 74 00 00 00 44 73 47 65 74 44 63 4E 61 6D 65 57 00 00 52 74 6C 45 71 75 61 6C 53 74 72 69 6E 67 00 00 43 6F 55 6E 69 6E 69 74 69 61 6C 69 7A 65}

    condition:
        filesize < 2MB and 5 of ($st*) and all of ($iat*)
}

rule coi_mod_heur
{
    meta:
        description = "Heuristics for modules"
		author = "NCCIC ICS-CERT"
    
    condition:
        filesize < 2MB and pe.exports("Crash") and pe.number_of_exports < 5
}