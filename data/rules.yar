/*
 * Sample YARA rules for the antivirus.
 * Load with:  avscan --yara data/rules.yar <path>
 *        or:  avdaemon --yara data/rules.yar ...
 */

rule Eicar_Test_File
{
    meta:
        description = "EICAR anti-malware test string"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
