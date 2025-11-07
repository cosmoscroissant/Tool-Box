/*
 * YARA Rule: ASM_Footprint_00000000
 * Generated: 0000-00-00 00:00:00
 * 
 * Auto-Generated from Analysis of 2 Sample(s)
 * Total IOCs: 113 across 12 categories
 * 
 * Categories:
 *   bitcoin_wallets: 28
 *   files: 22
 *   universal_paths: 19
 *   custom_strings: 15
 *   suspicious_string: 10
 *   windows_commands: 5
 *   indicator_strings: 5
 *   protocols_full: 2
 *   urls: 2
 *   command_line_strings: 2
 *   format_string_commands: 2
 *   domains: 1
 * 
 * Detection Strategy:
 *   Tier 1: High Confidence indicators (crypto wallets)
 *   Tier 2: Medium Confidence (commands, URLs, specific paths)
 *   Tier 3: Combined Low and Medium Confidence
 *   Tier 4: Broad Match (multiple indicators)
 */
rule ASM_Footprint_00000000
{
    meta:
        description = "Auto-Generated YARA Rule from ASM Footprint Analysis"
        author = "ASM Footprint Sniffer"
        date = "0000-00-00"
        version = "1.0"
        sample_sha256 = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
        sample_md5 = "db349b97c37d22f5ea1d1841e3c89eb4"
        total_indicators = "113"
        categories = "12"

    strings:
        $path_0 = "Global\\\\MsWinZonesCacheCounterMutexA" nocase wide ascii
        $path_1 = "Global\\MsWinZonesCacheCounterMutexA" nocase wide ascii
        $path_2 = "C:\\%s\\qeriuwjhrf" nocase wide ascii
        $path_3 = "C:\\\\%s\\\\qeriuwjhrf" nocase wide ascii
        $path_4 = "%s\\\\ProgramData" nocase wide ascii
        $path_5 = "%s\\ProgramData" nocase wide ascii
        $path_6 = "Software\\\\" nocase wide ascii
        $path_7 = "%s\\Intel" nocase wide ascii
        $path_8 = "%s\\\\Intel" nocase wide ascii
        $path_9 = "\\\\%s\\IPC$" nocase wide ascii
        $path_10 = "\\\\\\\\%s\\\\IPC$" nocase wide ascii
        $path_11 = "C:\\%s\\%s" nocase wide ascii
        $path_12 = "C:\\\\%s\\\\%s" nocase wide ascii
        $path_13 = "/..\\\\" nocase wide ascii
        $path_14 = "\\\\../" nocase wide ascii
        $path_15 = "\\\\..\\\\" nocase wide ascii
        $fname_16 = "surijfaewrwergwea.com" nocase ascii
        $fname_17 = "OLEAUT32.dll" nocase ascii
        $fname_18 = "MSVCP60.dll" nocase ascii
        $fname_19 = "ADVAPI32.dll" nocase ascii
        $fname_20 = "KERNEL32.dll" nocase ascii
        $fname_21 = "MSVCRT.dll" nocase ascii
        $fname_22 = "USER32.dll" nocase ascii
        $fname_23 = "SHELL32.dll" nocase ascii
        $fname_24 = "tasksche.exe" nocase ascii
        $fname_25 = "WININET.dll" nocase ascii
        $fname_26 = "WS2_32.dll" nocase ascii
        $fname_27 = "iphlpapi.dll" nocase ascii
        $fname_28 = "cmd.exe" nocase ascii
        $susp_29 = "0_Lockit@std" nocase ascii
        $susp_30 = "1_Lockit@std" nocase ascii
        $susp_31 = "WNcry@2ol7" nocase ascii
        $susp_32 = "_WinMain@16" nocase ascii
        $susp_33 = "YAPAXI@Z" nocase ascii
        $susp_34 = "UAE@XZ" nocase ascii
        $susp_35 = "QAE@XZ" nocase ascii
        $susp_36 = "YAXPAX@Z" nocase ascii
        $btc_37 = "3D2nRt9wLJmA44P8hcsWfuNL7SRflVzXQHc" ascii
        $btc_38 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
        $btc_39 = "3g08sJ5IIvrDPUg9UDxblaYNQjYb2zirFVO" ascii
        $btc_40 = "1n6CQZn5FObY8LvAFP7wJQNGxh4wIin9TF9" ascii
        $btc_41 = "1E1TMadDs0nlbPlGBftJmUsG7mvQfgv4XYX" ascii
        $btc_42 = "1IiqBm2TMu6vR8ISFbSJMgLtedMtOpDMjvX" ascii
        $btc_43 = "3Q3bKY4mQGAT5ptJdS4cPnRuhyaUgGdABBu" ascii
        $btc_44 = "3yNhHJhcnGqyI1nFFSiHLzRfbzT5nDJWj20" ascii
        $btc_45 = "1QLIx87qMRxXTwTDP690T6BmRPwbnDjLrdc" ascii
        $btc_46 = "1cT5EzU5oIR7Sj5jVO7miqlawsIW33Wxlqh" ascii
        $btc_47 = "3CXM7P0q8SIiNebTjCmERyc8gaTh7IiN8g2" ascii
        $btc_48 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw" ascii
        $btc_49 = "1Oe4sfNcUHLpDtHW05OCUj7HyIV1cOr2a" ascii
        $btc_50 = "1D5hn82L2KejU4OnLaNrMFiGieF4C53LX7M" ascii
        $btc_51 = "11fB8idliLHC2l1nYd2tklRf04bSMxBlcZa" ascii
        $btc_52 = "19HE4ctdxuhxCXMh2oQfHkYe2cxb1Y3Q6uH" ascii
        $btc_53 = "1MdKiBVBsf10KiFSGBxBEBSIUGcwj7NWJmE" ascii
        $btc_54 = "3LB0Yi5Wjp0t2It2PyrnnzZsgKGv" ascii
        $btc_55 = "3hIycfQUnnzWBhAHD95r8ITOsP1f" ascii
        $btc_56 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii
        $btc_57 = "3z9XR9rS0gpX9YYbuxOvXgcEhj8A4G" ascii
        $btc_58 = "1Y4dYgvVmE9JSmet0QqeSEB5gFqS8ae8I" ascii
        $btc_59 = "34VNQ2uQRSspH9b4QaNlc3QHOSu0ZyWgl" ascii
        $btc_60 = "3ftxH95kTkKdGtEbMfbdMxurHPTBKTm5MG6" ascii
        $btc_61 = "1oJGT5WeYPevOCpQJUGBZavDgjC" ascii
        $btc_62 = "1O8h7UMITpVrhQvkEMcrDODxVi6" ascii
        $btc_63 = "1LVWtUkgqM0cPkq7k6KEwW7ued" ascii
        $btc_64 = "3GN5G5hzthnw2zIj0irwsbGLd3o" ascii
        $wcmd_65 = "icacls . /grant Everyone:F /T /C /Q" nocase ascii
        $wcmd_66 = "cmd.exe /c \"%s\"',0" nocase ascii
        $wcmd_67 = "attrib +h .',0" nocase ascii
        $wcmd_68 = "cmd.exe /c \\\"%s\\" nocase ascii
        $custom_69 = "text \"UTF-16LE\", 'WanaCrypt0r',0" nocase ascii
        $custom_70 = "push    offset aWanacry ; \"WANACRY!\"" nocase ascii
        $custom_71 = "push    offset Source   ; \"WanaCrypt0r\"" nocase ascii
        $custom_72 = "aWanacry db 'WANACRY!',0" nocase ascii
        $custom_73 = "push    offset aTWnry   ; \"t.wnry\"" nocase ascii
        $custom_74 = "push    offset Str2     ; \"c.wnry\"" nocase ascii
        $custom_75 = "aTWnry db 't.wnry',0" nocase ascii
        $custom_76 = "Str2 db 'c.wnry',0" nocase ascii
        $custom_77 = "CHAR aTWnry[]" nocase ascii
        $ind_78 = "Microsoft Security Center (2.0) Service" nocase ascii
        $ind_79 = "attrib +h ." nocase ascii
        $ind_80 = "tasksche.exe" nocase ascii
        $ind_81 = "kernel32.dll" nocase ascii
        $ind_82 = "mssecsvc2.0" nocase ascii
        $url_83 = "http://www.iuqerfsodp9ifjaposdfjhgosuri" nocase ascii
        $url_84 = "http://www.iuqerfsodp9ifjaposdfjhgosuri" nocase ascii
        $domain_85 = "surijfaewrwergwea.com" nocase ascii
        $cmdline_86 = "C:\\%s\\qeriuwjhrf" nocase ascii
        $cmdline_87 = "C:\\\\%s\\\\qeriuwjhrf" nocase ascii
        $fmt_88 = "'%s -m security',0" nocase ascii

    condition:
        ($btc_37 or $btc_38 or $btc_39 or $btc_40 or $btc_41 or $btc_42 or $btc_43 or $btc_44 or $btc_45 or $btc_46) or

        2 of ($wcmd_65, $wcmd_66, $wcmd_67, $wcmd_68, $url_83, $url_84, $fmt_88) or

        (3 of ($domain_85, $fname_16, $fname_17, $fname_18, $fname_19, $fname_20, $susp_29, $susp_30, $susp_31, $susp_32, $susp_33, $custom_69, $custom_70, $custom_71, $custom_72, $custom_73, $ind_78, $ind_79, $ind_80, $ind_81, $ind_82) and 1 of ($wcmd_65, $wcmd_66, $wcmd_67, $wcmd_68, $url_83)) or

        5 of them
}