import "hash"

// Original defensive rules, 2026-10-28. Externals are provided PER FILE by
// hosthunt.py: scope={web,session,artifact,capture}, filename=<basename>.
// Matching indicates the evidence class in metadata, never automatic RCE proof.

rule PHP2SHELL_Associated_Malware_Exact_SHA256 : known_malware
{
    meta:
        author = "CyberOK"
        date = "2026-10-28"
        evidence = "known_malware_sample"
        confidence = "high_for_sample_identity_not_initial_access"
        reference = "https://cowrai.com/research/php2shell-godofthunder/"
        caveat = "Associated loader/bot; source emulates PHP. A match does not attribute initial access to these CVEs."
    condition:
        filesize > 0 and filesize <= 4MB and
        (hash.sha256(0, filesize) == "4d02f14d109458cb0d696b65456918fcd724ca385aa30c688f08554c8899938c" or
         hash.sha256(0, filesize) == "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486")
}

rule PHP2SHELL_PublicPoC_8512_Named_Shell : public_poc
{
    meta:
        evidence = "known_poc_shell_content"
        confidence = "high_for_poc_similarity_not_execution"
        reference = "https://github.com/rafalohaki/php2shell-poc/blob/6102cff317b4b7ae9188fc8e82f6a4a64e6fd950/php2shell-8512/exploit/php2shell_8512.py"
        caveat = "Research files and authorized testing can match. Filename alone is insufficient."
    strings:
        $php = "<?php" nocase
        $short = "<?="
        $direct = /\b(system|shell_exec|exec|passthru)[ \t\r\n]{0,32}\([ \t\r\n]{0,32}\$_(GET|POST|REQUEST)[ \t\r\n]{0,16}\[/ nocase
    condition:
        (scope == "web" or scope == "artifact") and filesize <= 64MB and
        filename == "p2s_8512_shell.php" and ($php or $short) and $direct
}

rule PHP2SHELL_PublicPoC_Session_Webshell : public_poc
{
    meta:
        evidence = "known_poc_shell_content"
        confidence = "high_for_poc_similarity_not_execution"
        reference = "https://github.com/rafalohaki/php2shell-poc/blob/6102cff317b4b7ae9188fc8e82f6a4a64e6fd950/webshell/session_webshell.py"
        caveat = "Separate PoC from p2s_8512_shell.php. Matching stored code does not establish inclusion/execution."
    strings:
        $php = "<?php" nocase
        $alive = "SHELL_ALIVE"
        $persist = "PAYLOAD_PERSISTED sid="
        $exec = "shell_exec"
    condition:
        (scope == "session" or scope == "web") and filesize <= 64MB and all of them
}

rule PHP2SHELL_Session_UploadProgress_PHP : session_hunt
{
    meta:
        evidence = "suspicious_stored_input"
        confidence = "medium"
        reference = "https://www.php.net/manual/en/session.configuration.php"
        caveat = "Default prefix only. User filenames, snippets and Safechecks may match; not proof of execution."
    strings:
        $progress = "upload_progress_"
        $php = "<?php" nocase
        $short = "<?="
    condition:
        scope == "session" and filesize <= 64MB and $progress and ($php or $short)
}

rule PHP2SHELL_Session_Progress_ObjectSeed : session_hunt
{
    meta:
        evidence = "suspicious_serialized_progress_key"
        confidence = "medium"
        reference = "https://github.com/rafalohaki/php2shell-poc/blob/6102cff317b4b7ae9188fc8e82f6a4a64e6fd950/php2shell-8512/exploit/php2shell_8512.py"
        caveat = "Default prefix and bounded context. Does not match ordinary key|a or key|O by itself. Tests can match."
    strings:
        $seed = /upload_progress_[^|\x00\r\n]{0,160}\|[OC]:[0-9]{1,5}:"/
    condition:
        scope == "session" and filesize <= 64MB and $seed
}

rule PHP_Direct_Request_Execution_Heuristic : generic_php
{
    meta:
        evidence = "generic_dangerous_php_pattern"
        confidence = "medium"
        reference = "Locally authored heuristic; not specific to PHP2Shell or any CVE"
        caveat = "Can match examples/admin tools. Misses obfuscation, variable indirection and other execution mechanisms."
    strings:
        $php = "<?php" nocase
        $short = "<?="
        $direct = /\b(system|shell_exec|exec|passthru|eval|assert)[ \t\r\n]{0,32}\([ \t\r\n]{0,32}\$_(GET|POST|REQUEST|COOKIE)[ \t\r\n]{0,16}\[/ nocase
    condition:
        (scope == "web" or scope == "artifact") and filesize <= 64MB and
        ($php or $short) and $direct
}

rule PHP2SHELL_Captured_Integer_Key_Sequence : captured_attack_material
{
    meta:
        evidence = "captured_request_pattern"
        confidence = "medium"
        reference = "https://github.com/corelight/php2shell-detect/blob/3b3715aa6ce50b6c2a8b03d2863506645b364b98/suricata/php2shell.rules"
        caveat = "Inspired by SID3000653. Scan one decoded request body per file; no execution inference."
    strings:
        $sequence = /i:4294967296;[\x00-\xFF]{0,48}i:8589934592;[\x00-\xFF]{0,48}i:12884901888;/
    condition:
        scope == "capture" and filesize <= 64MB and $sequence
}
