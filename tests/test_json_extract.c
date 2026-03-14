/*
 * test_json_extract.c — Unit tests for json_extract_string() escape decoding
 *
 * Tests the minimal JSON parser in virp_onode.c to ensure all JSON escape
 * sequences are decoded correctly, especially \n which broke multi-line
 * config blocks.
 *
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "virp_onode.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  [%02d] %-50s ", tests_run, name); \
    } while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

/* ── Test cases ─────────────────────────────────────────────────── */

static void test_simple_extraction(void)
{
    TEST("Simple string extraction");
    char out[256];
    const char *json = "{\"name\": \"hello world\"}";
    bool ok = json_extract_string(json, "name", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strcmp(out, "hello world") != 0) { FAIL(out); return; }
    PASS();
}

static void test_newline_escape(void)
{
    TEST("Newline \\n decoding (the bug that bit us)");
    char out[256];
    const char *json = "{\"config\": \"line1\\nline2\\nline3\"}";
    bool ok = json_extract_string(json, "config", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strcmp(out, "line1\nline2\nline3") != 0) {
        FAIL("newlines not decoded");
        return;
    }
    PASS();
}

static void test_mixed_escapes(void)
{
    TEST("Mixed escapes: \\t \\r \\\\ \\\"");
    char out[256];
    const char *json = "{\"data\": \"col1\\tcol2\\r\\n\\\\path\\\\to\\\"file\\\"\"}";
    bool ok = json_extract_string(json, "data", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strcmp(out, "col1\tcol2\r\n\\path\\to\"file\"") != 0) {
        FAIL("mixed escapes wrong");
        return;
    }
    PASS();
}

static void test_unicode_escape_ascii(void)
{
    TEST("Unicode escape \\u0041 -> A");
    char out[256];
    const char *json = "{\"ch\": \"\\u0041\"}";
    bool ok = json_extract_string(json, "ch", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strcmp(out, "A") != 0) { FAIL("not 'A'"); return; }
    PASS();
}

static void test_unicode_escape_bmp(void)
{
    TEST("Unicode escape \\u00E9 -> e-acute (UTF-8)");
    char out[256];
    const char *json = "{\"ch\": \"caf\\u00E9\"}";
    bool ok = json_extract_string(json, "ch", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    /* UTF-8 for U+00E9: 0xC3 0xA9 */
    if (strcmp(out, "caf\xC3\xA9") != 0) { FAIL("UTF-8 mismatch"); return; }
    PASS();
}

static void test_unicode_surrogate_replaced(void)
{
    TEST("Unicode surrogate \\uD800 -> ? replacement");
    char out[256];
    const char *json = "{\"ch\": \"\\uD800\"}";
    bool ok = json_extract_string(json, "ch", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strcmp(out, "?") != 0) { FAIL("not '?'"); return; }
    PASS();
}

static void test_empty_string(void)
{
    TEST("Empty string value");
    char out[256];
    out[0] = 'X';  /* ensure it gets overwritten */
    const char *json = "{\"empty\": \"\"}";
    bool ok = json_extract_string(json, "empty", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (out[0] != '\0') { FAIL("not empty"); return; }
    PASS();
}

static void test_key_not_found(void)
{
    TEST("Key not found returns false");
    char out[256];
    const char *json = "{\"name\": \"value\"}";
    bool ok = json_extract_string(json, "missing", out, sizeof(out));
    if (ok) { FAIL("should have returned false"); return; }
    PASS();
}

static void test_buffer_too_small(void)
{
    TEST("Buffer too small — no overflow");
    char out[4];  /* only room for 3 chars + null */
    const char *json = "{\"name\": \"abcdefghij\"}";
    bool ok = json_extract_string(json, "name", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strlen(out) != 3) { FAIL("wrong length"); return; }
    if (strcmp(out, "abc") != 0) { FAIL("wrong content"); return; }
    PASS();
}

static void test_nested_quotes(void)
{
    TEST("Nested escaped quotes in value");
    char out[256];
    const char *json = "{\"msg\": \"he said \\\"hello\\\" to me\"}";
    bool ok = json_extract_string(json, "msg", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strcmp(out, "he said \"hello\" to me") != 0) {
        FAIL("nested quotes wrong");
        return;
    }
    PASS();
}

static void test_slash_and_backspace(void)
{
    TEST("Forward slash \\/ and backspace \\b and formfeed \\f");
    char out[256];
    const char *json = "{\"path\": \"a\\/b\\bc\\fd\"}";
    bool ok = json_extract_string(json, "path", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if (strcmp(out, "a/b\bc\fd") != 0) { FAIL("wrong value"); return; }
    PASS();
}

static void test_multiline_config_block(void)
{
    TEST("Multi-line config block (real-world scenario)");
    char out[1024];
    const char *json =
        "{\"command\": \"show run\", \"output\": "
        "\"interface Loopback0\\n ip address 10.0.0.1 255.255.255.255\\n!\\n"
        "router ospf 1\\n network 10.0.0.0 0.0.0.255 area 0\"}";
    bool ok = json_extract_string(json, "output", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    const char *expected =
        "interface Loopback0\n ip address 10.0.0.1 255.255.255.255\n!\n"
        "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0";
    if (strcmp(out, expected) != 0) {
        int nl = 0;
        for (size_t j = 0; out[j]; j++) if (out[j] == '\n') nl++;
        printf("FAIL: newline count=%d (expected 4)\n", nl);
        tests_failed++;
        return;
    }
    PASS();
}

static void test_unicode_3byte(void)
{
    TEST("Unicode 3-byte BMP \\u4E16 -> UTF-8");
    char out[256];
    /* U+4E16 = CJK character -> UTF-8: E4 B8 96 */
    const char *json = "{\"ch\": \"\\u4E16\"}";
    bool ok = json_extract_string(json, "ch", out, sizeof(out));
    if (!ok) { FAIL("returned false"); return; }
    if ((unsigned char)out[0] != 0xE4 ||
        (unsigned char)out[1] != 0xB8 ||
        (unsigned char)out[2] != 0x96 ||
        out[3] != '\0') {
        FAIL("UTF-8 bytes mismatch");
        return;
    }
    PASS();
}

/* ── Main ──────────────────────────────────────────────────────── */

int main(void)
{
    printf("\n=== test_json_extract: JSON escape decoding tests ===\n\n");

    test_simple_extraction();
    test_newline_escape();
    test_mixed_escapes();
    test_unicode_escape_ascii();
    test_unicode_escape_bmp();
    test_unicode_surrogate_replaced();
    test_empty_string();
    test_key_not_found();
    test_buffer_too_small();
    test_nested_quotes();
    test_slash_and_backspace();
    test_multiline_config_block();
    test_unicode_3byte();

    printf("\n--- Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(" (%d FAILED)", tests_failed);
    printf(" ---\n\n");

    return tests_failed > 0 ? 1 : 0;
}
