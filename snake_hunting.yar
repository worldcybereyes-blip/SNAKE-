import "pe"

rule SNAKE_Hunt_Encrypted_Store_Filename
{
    meta:
        description = "Hunting lead: references the encrypted storage filename publicly associated with SNAKE"
        confidence = "LOW"
        reference = "CISA AA23-129A, validate before production use"
        author = "SNAKE project"
        purpose = "triage sweep of disk images and process memory"

    strings:
        $s1 = "comadmin.dat" ascii wide nocase

    condition:
        any of them and filesize < 20MB
}

rule SNAKE_Hunt_Named_Pipe_Strings
{
    meta:
        description = "Hunting lead: named pipe strings cited in public vendor research on Uroburos"
        confidence = "LOW"
        reference = "Public vendor research, verify against primary sources"
        author = "SNAKE project"
        purpose = "memory dump triage"

    strings:
        $p1 = "\\\\.\\pipe\\sdlrpc" ascii wide nocase
        $p2 = "\\\\.\\pipe\\comnap" ascii wide nocase

    condition:
        any of them
}

rule SNAKE_Hunt_Service_Dll_Outside_System32
{
    meta:
        description = "Structural hunting lead: PE exporting ServiceMain, small size, no version info resource"
        confidence = "LOW"
        reference = "Structural heuristic, expect false positives"
        author = "SNAKE project"
        purpose = "review of unsigned service libraries on a triage image"

    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        pe.is_dll() and
        pe.exports("ServiceMain") and
        pe.number_of_resources == 0
}
