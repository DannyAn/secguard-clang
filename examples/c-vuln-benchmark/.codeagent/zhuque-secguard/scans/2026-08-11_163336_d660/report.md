# SecGuard Security Scan Report

**Scan ID:** 2026-08-11_163336_d660
**Tool:** zhuque-secguard v0.1.0

## Summary

| Metric | Value |
|--------|-------|
| Files indexed | 15 |
| Functions indexed | 103 |
| Total candidates | 89 |
| Vulnerability types | 14 |

## Candidates by Type

| Type | CWE | Count |
|------|-----|-------|
| buffer-overflow | CWE-787 | 27 |
| crypto-misuse | CWE-327 | 5 |
| deadlock | CWE-667 | 1 |
| double-free | CWE-415 | 2 |
| format-string | CWE-134 | 1 |
| hardcoded-secret | CWE-798 | 3 |
| injection | CWE-78 | 6 |
| integer-overflow | CWE-190 | 2 |
| memory-leak | CWE-401 | 2 |
| null-deref | CWE-476 | 23 |
| race-condition | CWE-362 | 2 |
| resource-leak | CWE-404 | 5 |
| uninit | CWE-457 | 9 |
| use-after-free | CWE-416 | 1 |

## buffer-overflow (CWE-787)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | process_buffer_unsafe | src/p2_raii_memory.c:62 | memcpy(buf, input, len) | suspected |
| 2 | parse_task_name | src/parser.c:20 | strcpy(task->name, input) | suspected |
| 3 | write_user_file | src/windows.c:22 | strcat(path, filename) | suspected |
| 4 | alloc_user_buffer | src/allocator.c:99 | strcpy(buf, "initialized") | suspected |
| 5 | allocate_and_forget | src/memory_extra.c:58 | strcpy(buf, "temporary") | suspected |
| 6 | mismatched_free_example | src/memory_extra.c:69 | strcpy(buf, "test") | suspected |
| 7 | process_user_data_unsafe | src/p1_safecopy_wrapper.c:47 | memcpy(buf, user_input, strlen(user_input)) | suspected |
| 8 | copy_message_unsafe | src/p2_bounds_checked.c:37 | memcpy(dst, src, user_len) | suspected |
| 9 | process_buffer | src/p2_raii_memory.c:46 | memcpy(handle->data, input, len) | suspected |
| 10 | validate_user_input | src/parser.c:77 | strcpy(buf, user_input) | suspected |
| 11 | alloc_entry | src/allocator.c:31 | g_entries[g_entry_count++] | suspected |
| 12 | find_unused_entry | src/allocator.c:38 | g_entries[i] | suspected |
| 13 | find_unused_entry | src/allocator.c:39 | g_entries[i] | suspected |
| 14 | cleanup_entries | src/allocator.c:60 | g_entries[i] | suspected |
| 15 | cleanup_entries | src/allocator.c:61 | g_entries[i] | suspected |
| 16 | cleanup_entries | src/allocator.c:62 | g_entries[i] | suspected |
| 17 | cleanup_entries | src/allocator.c:63 | g_entries[i] | suspected |
| 18 | heap_overflow_example | src/memory_extra.c:15 | buf[i] | suspected |
| 19 | parse_packet | src/network.c:56 | packet->data[i] | suspected |
| 20 | parse_packet | src/network.c:60 | packet_queue[queue_size++] | suspected |
| 21 | process_packets | src/network.c:73 | packet_queue[i] | suspected |
| 22 | cleanup_packets | src/network.c:84 | packet_queue[i] | suspected |
| 23 | cleanup_packets | src/network.c:85 | packet_queue[i] | suspected |
| 24 | cleanup_packets | src/network.c:86 | packet_queue[i] | suspected |
| 25 | cleanup_packets | src/network.c:87 | packet_queue[i] | suspected |
| 26 | off_by_one_example | src/memory_extra.c:90 | buf[i] | suspected |
| 27 | oob_read_example | src/parser.c:86 | arr[i] | suspected |

## crypto-misuse (CWE-327)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | generate_token_weak | src/crypto.c:29 | srand(time(NULL)) | suspected |
| 2 | generate_token_weak | src/crypto.c:30 | rand() | suspected |
| 3 | encrypt_data_weak | src/crypto.c:49 | DES_set_key_unchecked(&key, &schedule) | suspected |
| 4 | encrypt_data_weak | src/crypto.c:52 | DES_ecb_encrypt((const_DES_cblock *)plaintext,
                    (DES_cblock *)output, &schedule, DES_ENCRYPT) | suspected |
| 5 | authenticate_user | src/crypto.c:69 |  | suspected |

## deadlock (CWE-667)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | thread_deadlock_a | src/concurrency.c:38 |  | suspected |

## double-free (CWE-415)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | main | src/allocator.c:123 | e1 | suspected |
| 2 | main | src/allocator.c:123 | e2 | suspected |

## format-string (CWE-134)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | log_user_message | src/parser.c:45 | printf(user_msg) | suspected |

## hardcoded-secret (CWE-798)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | authenticate_user | src/crypto.c:12 | g_api_key | suspected |
| 2 | authenticate_user | src/crypto.c:17 | password | suspected |
| 3 | authenticate_user | src/crypto.c:18 | token | suspected |

## injection (CWE-78)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | run_admin_command | src/p3_edge_case.c:28 | system(cmd) | suspected |
| 2 | safe_command_execution | src/p0_safe_functions.c:60 | execv("/bin/ls", argv2) | suspected |
| 3 | execute_user_command | src/system.c:15 | system(cmd) | suspected |
| 4 | run_user_command | src/windows.c:13 | CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi) | suspected |
| 5 | lookup_user_unsafe | src/p1_safequery_wrapper.c:49 | sprintf(query, "SELECT * FROM users WHERE name = '%s'", username) | suspected |
| 6 | lookup_user_unsafe | src/p1_safequery_wrapper.c:50 | sqlite3_exec(db, query, NULL, NULL, NULL) | suspected |

## integer-overflow (CWE-190)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | parse_packet | src/network.c:38 | header->data_size + HEADER_SIZE > raw_size | suspected |
| 2 | parse_packet | src/network.c:38 | header->data_size + HEADER_SIZE | suspected |

## memory-leak (CWE-401)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | demo_unsafe_signal | src/concurrency.c:104 | g_global_ptr | suspected |
| 2 | leak_in_path | src/memory_extra.c:44 | buf | suspected |

## null-deref (CWE-476)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | find_unused_entry | src/allocator.c:38 | g_entries[i] | suspected |
| 2 | parse_packet | src/network.c:45 | packet | suspected |
| 3 | parse_packet | src/network.c:51 | packet | suspected |
| 4 | parse_packet | src/network.c:51 | header | suspected |
| 5 | parse_packet | src/network.c:52 | packet | suspected |
| 6 | parse_packet | src/network.c:52 | header | suspected |
| 7 | parse_packet | src/network.c:54 | packet | suspected |
| 8 | parse_packet | src/network.c:55 | header | suspected |
| 9 | parse_packet | src/network.c:56 | packet | suspected |
| 10 | parse_packet | src/network.c:56 | packet->data | suspected |
| 11 | parse_packet | src/network.c:62 | packet | suspected |
| 12 | parse_task_name | src/parser.c:20 | task | suspected |
| 13 | format_task_desc | src/parser.c:31 | task | suspected |
| 14 | format_task_desc | src/parser.c:33 | task | suspected |
| 15 | parse_args | src/parser.c:52 | argv | suspected |
| 16 | parse_args | src/parser.c:60 | argv | suspected |
| 17 | parse_args | src/parser.c:63 | argv | suspected |
| 18 | parse_args | src/parser.c:64 | argv | suspected |
| 19 | main | src/network.c:97 | hdr | confirmed |
| 20 | main | src/network.c:98 | hdr | confirmed |
| 21 | main | src/network.c:99 | hdr | confirmed |
| 22 | FileCache_create | src/p3_edge_case.c:68 | fc | confirmed |
| 23 | FileCache_create | src/p3_edge_case.c:69 | fc | confirmed |

## race-condition (CWE-362)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | check_and_transfer | src/p3_edge_case.c:49 |  | suspected |
| 2 | check_then_open | src/system.c:44 |  | suspected |

## resource-leak (CWE-404)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | increment_counter | src/p2_lock_guard.c:25 | g_mutex | suspected |
| 2 | process_file | src/p3_edge_case.c:83 | fc | suspected |
| 3 | run_user_command | src/windows.c:13 | si | suspected |
| 4 | run_user_command | src/windows.c:13 | pi | suspected |
| 5 | drop_and_elevate | src/windows.c:45 | hToken | suspected |

## uninit (CWE-457)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | process_flag | src/memory_extra.c:24 | flag | suspected |
| 2 | parse_args | src/parser.c:57 | task | suspected |
| 3 | parse_args | src/parser.c:60 | task | suspected |
| 4 | parse_args | src/parser.c:64 | task | suspected |
| 5 | parse_args | src/parser.c:67 | task | suspected |
| 6 | parse_args | src/parser.c:69 | task | suspected |
| 7 | drop_and_elevate | src/windows.c:45 | hToken | suspected |
| 8 | impersonate_logged_on_user | src/windows.c:54 | hToken | suspected |
| 9 | run_user_command | src/windows.c:13 | pi | suspected |

## use-after-free (CWE-416)

| # | Function | File:Line | Variable | Suspicion |
|---|----------|-----------|----------|----------|
| 1 | process_released_buffer | src/allocator.c:87 | buf | suspected |

## Output Files

- SARIF: `.codeagent/zhuque-secguard/scans/2026-08-11_163336_d660/sarif.sarif`
- Per-finding details: `<vuln-type>/<NNN>_<file>_<line>.md`
- Database: `.sgre/sgre.db`
