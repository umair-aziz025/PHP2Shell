/*
 * =============================================================================
 * PHP2Shell YARA Detection Rules
 * =============================================================================
 *
 * Purpose:   Detect PHP2Shell exploit tools, post-exploitation webshells,
 *            exploit artifacts in memory dumps, and known PoC code patterns
 *            on disk or in memory.
 *
 * CVEs:      CVE-2026-109618 (OOM → Uninitialized Memory Corruption)
 *            CVE-2026-109619 (Use-After-Free via stale global state)
 *
 * Deploy:    yara -r php2shell.yar /path/to/scan
 *            yara -p 8 php2shell.yar /var/www/
 *
 * Author:    PHP2Shell Research Project – Defensive Detection Team
 * Date:      2026-10-22
 * License:   BSD-3-Clause
 * =============================================================================
 */

import "pe"
import "elf"
import "math"


// ---------------------------------------------------------------------------
// Rule 1: PHP2Shell Exploit Tool Detection
// Identifies exploit scripts/binaries on disk by matching known code patterns,
// strings, and identifiers used in public PHP2Shell PoC tooling.
// ---------------------------------------------------------------------------

rule PHP2Shell_Exploit_Tool
{
    meta:
        description   = "Detects PHP2Shell exploit tools and PoC scripts on disk"
        author        = "PHP2Shell Research – Defensive Detection Team"
        date          = "2026-10-22"
        version       = "1.0"
        reference     = "CVE-2026-109618, CVE-2026-109619"
        severity      = "critical"
        tlp           = "white"
        hash          = "n/a"

    strings:
        // Tool identifiers and banner strings
        $tool_name1    = "php2shell" ascii wide nocase
        $tool_name2    = "PHP2Shell" ascii wide
        $tool_name3    = "PHP-OOM-Exploit" ascii wide
        $tool_name4    = "UAF-Trigger" ascii wide

        // CVE references commonly embedded in exploit source
        $cve1          = "CVE-2026-109618" ascii wide nocase
        $cve2          = "CVE-2026-109619" ascii wide nocase

        // Exploit-specific function/class names
        $func_oom      = "trigger_oom" ascii wide nocase
        $func_uaf      = "trigger_uaf" ascii wide nocase
        $func_spray    = "heap_spray" ascii wide nocase
        $func_corrupt  = "corrupt_memory" ascii wide nocase
        $func_exploit  = "exploit_worker" ascii wide nocase
        $func_race     = "race_condition" ascii wide nocase

        // Exploitation technique strings
        $tech_oom      = "memory_limit" ascii wide nocase
        $tech_mpart    = "multipart/form-data" ascii wide nocase
        $tech_fpm      = "php-fpm" ascii wide nocase
        $tech_worker   = "stale_worker" ascii wide nocase
        $tech_dangling = "dangling_pointer" ascii wide nocase

        // Python/script markers for PoC exploit scripts
        $py_requests   = "import requests" ascii
        $py_socket     = "import socket" ascii
        $py_struct     = "import struct" ascii
        $py_argparse   = "import argparse" ascii

    condition:
        // Must contain at least one tool identifier or CVE reference,
        // PLUS at least two exploit-specific function names or techniques
        (
            any of ($tool_name*) or any of ($cve*)
        )
        and
        (
            2 of ($func_*) or
            (1 of ($func_*) and 2 of ($tech_*))
        )
}


// ---------------------------------------------------------------------------
// Rule 2: PHP2Shell PoC Code Patterns
// More specific detection of known PoC source code structure — catches the
// exact exploit flow: OOM triggering → error recovery → UAF exploitation.
// ---------------------------------------------------------------------------

rule PHP2Shell_PoC_Source_Code
{
    meta:
        description   = "Detects PHP2Shell PoC exploit source code by structural patterns"
        author        = "PHP2Shell Research – Defensive Detection Team"
        date          = "2026-10-22"
        version       = "1.0"
        reference     = "CVE-2026-109618, CVE-2026-109619"
        severity      = "critical"
        tlp           = "white"

    strings:
        // Stage 1: OOM triggering via crafted requests
        $oom_stage1a   = "Content-Length" ascii wide
        $oom_stage1b   = /boundary=[\-a-zA-Z0-9]{16,}/ ascii
        $oom_stage1c   = "memory exhaustion" ascii wide nocase
        $oom_stage1d   = /alloc.*fail/ ascii nocase
        $oom_stage1e   = "ini_set" ascii wide

        // Stage 2: Error recovery / dangling pointer setup
        $uaf_stage2a   = "error_handler" ascii wide nocase
        $uaf_stage2b   = "zend_mm_heap" ascii wide nocase
        $uaf_stage2c   = "use_after_free" ascii wide nocase
        $uaf_stage2d   = "dangling" ascii wide nocase
        $uaf_stage2e   = "stale" ascii wide nocase

        // Stage 3: Worker reuse and exploitation
        $exploit_3a    = "same_worker" ascii wide nocase
        $exploit_3b    = "keep-alive" ascii wide nocase
        $exploit_3c    = "Connection: keep-alive" ascii wide nocase
        $exploit_3d    = /rapid.*request/ ascii nocase
        $exploit_3e    = "race" ascii wide nocase

        // Shellcode / payload stage
        $payload_a     = "shellcode" ascii wide nocase
        $payload_b     = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}/ ascii
        $payload_c     = "reverse_shell" ascii wide nocase
        $payload_d     = "bind_shell" ascii wide nocase
        $payload_e     = "mprotect" ascii wide nocase

    condition:
        filesize < 5MB and
        (
            // Full exploit chain: OOM + UAF + payload
            (2 of ($oom_stage1*) and 2 of ($uaf_stage2*) and 1 of ($payload_*))
            or
            // OOM + worker reuse chain
            (2 of ($oom_stage1*) and 2 of ($exploit_3*) and 1 of ($uaf_stage2*))
            or
            // UAF + payload without explicit OOM references
            (3 of ($uaf_stage2*) and 2 of ($payload_*))
        )
}


// ---------------------------------------------------------------------------
// Rule 3: Post-Exploitation Webshell Detection
// Identifies webshells that may have been dropped after successful
// PHP2Shell exploitation.  Matches common PHP webshell patterns plus
// indicators that the shell was deployed via memory corruption.
// ---------------------------------------------------------------------------

rule PHP2Shell_Webshell_PostExploit
{
    meta:
        description   = "Detects webshells potentially dropped via PHP2Shell exploitation"
        author        = "PHP2Shell Research – Defensive Detection Team"
        date          = "2026-10-22"
        version       = "1.0"
        reference     = "CVE-2026-109618, CVE-2026-109619"
        severity      = "high"
        tlp           = "white"

    strings:
        // PHP opening tags
        $php_open1     = "<?php" ascii nocase
        $php_open2     = "<?" ascii

        // Command execution functions
        $exec1         = "system(" ascii nocase
        $exec2         = "exec(" ascii nocase
        $exec3         = "passthru(" ascii nocase
        $exec4         = "shell_exec(" ascii nocase
        $exec5         = "popen(" ascii nocase
        $exec6         = "proc_open(" ascii nocase
        $exec7         = "pcntl_exec(" ascii nocase
        $exec8         = /`\$_(GET|POST|REQUEST|COOKIE)\[/ ascii

        // Obfuscation techniques common in post-exploit shells
        $obf1          = "base64_decode(" ascii nocase
        $obf2          = "str_rot13(" ascii nocase
        $obf3          = "gzinflate(" ascii nocase
        $obf4          = "gzuncompress(" ascii nocase
        $obf5          = "eval(" ascii nocase
        $obf6          = "assert(" ascii nocase
        $obf7          = "create_function(" ascii nocase
        $obf8          = "preg_replace" ascii nocase
        $obf9          = /\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ ascii

        // Network callback / reverse shell indicators
        $net1          = "fsockopen(" ascii nocase
        $net2          = "socket_create(" ascii nocase
        $net3          = "stream_socket_client(" ascii nocase
        $net4          = "curl_exec(" ascii nocase

        // File operations for persistence
        $file1         = "file_put_contents(" ascii nocase
        $file2         = "fwrite(" ascii nocase
        $file3         = "move_uploaded_file(" ascii nocase

        // PHP2Shell-specific webshell markers
        $marker1       = "php2shell" ascii wide nocase
        $marker2       = "p2s_shell" ascii wide nocase
        $marker3       = "oom_shell" ascii wide nocase
        $marker4       = "uaf_drop" ascii wide nocase

    condition:
        filesize < 1MB and
        1 of ($php_open*) and
        (
            // Direct webshell: PHP tag + exec + obfuscation
            (2 of ($exec*) and 2 of ($obf*))
            or
            // Reverse shell: PHP tag + exec + network callback
            (1 of ($exec*) and 1 of ($net*) and 1 of ($obf*))
            or
            // PHP2Shell-specific markers with any exec
            (1 of ($marker*) and 1 of ($exec*))
            or
            // Heavy obfuscation with input-controlled execution
            (3 of ($obf*) and $obf9)
            or
            // File drop + exec (persistence mechanism)
            (1 of ($exec*) and 1 of ($file*) and 1 of ($obf*) and 1 of ($net*))
        )
}


// ---------------------------------------------------------------------------
// Rule 4: PHP2Shell Exploit Artifacts in Memory Dumps
// Detects remnants of PHP2Shell exploitation in process memory dumps,
// coredumps, or forensic RAM captures.
// ---------------------------------------------------------------------------

rule PHP2Shell_Memory_Artifact
{
    meta:
        description   = "Detects PHP2Shell exploitation artifacts in memory dumps"
        author        = "PHP2Shell Research – Defensive Detection Team"
        date          = "2026-10-22"
        version       = "1.0"
        reference     = "CVE-2026-109618, CVE-2026-109619"
        severity      = "critical"
        tlp           = "white"

    strings:
        // PHP internal structure corruption signatures
        $heap_corrupt1 = "zend_mm_heap corrupted" ascii wide
        $heap_corrupt2 = "double free or corruption" ascii wide
        $heap_corrupt3 = "corrupted size vs. prev_size" ascii wide
        $heap_corrupt4 = "free(): invalid pointer" ascii wide
        $heap_corrupt5 = "malloc(): memory corruption" ascii wide

        // PHP-FPM worker crash indicators
        $fpm_crash1    = "child exited on signal 11" ascii
        $fpm_crash2    = "child exited on signal 6" ascii
        $fpm_crash3    = "SIGSEGV" ascii
        $fpm_crash4    = "SIGABRT" ascii

        // Heap spray patterns (repeated 8-byte aligned pointers)
        // Common fake zval/zend_string structures used in exploitation
        $spray1        = { 06 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 }
        $spray2        = { 08 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 }

        // NOP sled in process memory
        $nopsled       = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                           90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

        // Shellcode markers commonly seen after PHP2Shell exploitation
        $sc_execve     = { 48 31 c0 48 89 c2 48 89 c6 48 8d 3d }  // x64 execve setup
        $sc_binsh      = "/bin/sh" ascii
        $sc_syscall    = { 0f 05 }  // syscall instruction

        // PHP2Shell tool strings that persist in memory
        $tool_mem1     = "php2shell" ascii wide nocase
        $tool_mem2     = "CVE-2026-10961" ascii  // Partial CVE match
        $tool_mem3     = "trigger_oom" ascii
        $tool_mem4     = "trigger_uaf" ascii
        $tool_mem5     = "exploit_worker" ascii

        // OOM error strings from PHP runtime
        $oom_err1      = "Allowed memory size of" ascii
        $oom_err2      = "tried to allocate" ascii

    condition:
        // Memory dumps are typically large; no strict filesize limit
        (
            // Heap corruption + PHP crash indicators
            (2 of ($heap_corrupt*) and 1 of ($fpm_crash*))
            or
            // Heap spray patterns + shellcode
            (1 of ($spray*) and ($nopsled or $sc_execve or ($sc_binsh and $sc_syscall)))
            or
            // PHP2Shell tool strings + corruption evidence
            (1 of ($tool_mem*) and 1 of ($heap_corrupt*))
            or
            // OOM + heap corruption chain
            (1 of ($oom_err*) and 2 of ($heap_corrupt*))
            or
            // Shellcode + tool markers in same dump
            ($sc_binsh and $sc_syscall and 1 of ($tool_mem*))
        )
}


// ---------------------------------------------------------------------------
// Rule 5: PHP2Shell Compiled Exploit Binary
// Detects compiled (ELF/PE) exploit binaries that target these CVEs.
// ---------------------------------------------------------------------------

rule PHP2Shell_Compiled_Exploit
{
    meta:
        description   = "Detects compiled PHP2Shell exploit binaries (ELF or PE)"
        author        = "PHP2Shell Research – Defensive Detection Team"
        date          = "2026-10-22"
        version       = "1.0"
        reference     = "CVE-2026-109618, CVE-2026-109619"
        severity      = "critical"
        tlp           = "white"

    strings:
        $s_cve1        = "CVE-2026-109618" ascii wide
        $s_cve2        = "CVE-2026-109619" ascii wide
        $s_tool        = "php2shell" ascii wide nocase
        $s_oom         = "trigger_oom" ascii wide
        $s_uaf         = "trigger_uaf" ascii wide
        $s_spray       = "heap_spray" ascii wide
        $s_exploit     = "exploit_worker" ascii wide
        $s_target      = "target_host" ascii wide
        $s_port        = "target_port" ascii wide
        $s_shell       = "reverse_shell" ascii wide
        $s_payload     = "payload_buf" ascii wide
        $s_corrupt     = "corrupt_zval" ascii wide

    condition:
        (
            // ELF binary
            (uint32(0) == 0x464C457F) or
            // PE binary
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        )
        and filesize < 50MB
        and
        (
            // CVE reference + exploit functions
            (1 of ($s_cve*) and 2 of ($s_oom, $s_uaf, $s_spray, $s_exploit))
            or
            // Tool name + multiple exploit indicators
            ($s_tool and 3 of ($s_*))
        )
}


// ---------------------------------------------------------------------------
// Rule 6: Obfuscated PHP Payload (Generic Webshell w/ Entropy Check)
// Catches heavily obfuscated PHP files that use high-entropy blobs—common
// in payloads dropped after memory corruption exploitation.
// ---------------------------------------------------------------------------

rule PHP2Shell_Obfuscated_Payload
{
    meta:
        description   = "Detects heavily obfuscated PHP payloads (high entropy + eval)"
        author        = "PHP2Shell Research – Defensive Detection Team"
        date          = "2026-10-22"
        version       = "1.0"
        reference     = "CVE-2026-109618, CVE-2026-109619"
        severity      = "high"
        tlp           = "white"

    strings:
        $php_tag       = "<?php" ascii nocase
        $eval          = "eval(" ascii nocase
        $assert        = "assert(" ascii nocase
        $b64           = "base64_decode(" ascii nocase
        $gz            = "gzinflate(" ascii nocase
        $rot           = "str_rot13(" ascii nocase
        $chr           = /chr\s*\(\s*\d+\s*\)/ ascii
        $hex_str       = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){30,}/ ascii

    condition:
        filesize < 2MB and
        $php_tag and
        (
            // eval + base64 + high entropy section
            ($eval and $b64 and math.entropy(0, filesize) > 5.5)
            or
            // Multiple obfuscation layers
            (3 of ($eval, $assert, $b64, $gz, $rot) and math.entropy(0, filesize) > 5.0)
            or
            // Direct hex-encoded payload with eval
            ($hex_str and ($eval or $assert))
            or
            // chr() construction with eval (character-by-character assembly)
            (#chr > 20 and ($eval or $assert))
        )
}
