#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

/*
    test_harness.h — Minimal Test Framework

    This is a self-contained test harness. It uses nothing beyond <stdio.h>
    and <stdlib.h> — no external test library required. This is consistent
    with the project's philosophy: no magic, no black boxes.

    HOW IT WORKS:

    We maintain two counters — tests_run and tests_failed — as simple
    global integers. Each test case calls CHECK() with an expression.
    If the expression is true, the test passes silently. If false,
    the macro prints the file, line number, and failing expression,
    then increments the failure counter.

    At the end of a test file, call TEST_SUMMARY() to print a pass/fail
    line and return a non-zero exit code if any tests failed.

    USAGE IN A TEST FILE:

        #include "test_harness.h"
        #include "netbuf.h"

        int main(void) {
            netbuf_t buf;
            CHECK(netbuf_init(&buf) == NET_OK);
            CHECK(netbuf_is_empty(&buf) == 1);
            TEST_SUMMARY();
        }

    The exit code from TEST_SUMMARY() lets the Makefile detect failures:
        make test  — runs all tests and reports overall pass/fail.
*/

#include <stdio.h>
#include <stdlib.h>

/* Global counters, defined once per test binary via this header. */
static int tests_run    = 0;
static int tests_failed = 0;

/*
    CHECK(expr) — Assert that expr is true (non-zero).

    If expr evaluates to 0 (false), prints the failure location and
    increments the failure counter. Either way, increments tests_run.

    We use a do { } while(0) wrapper so the macro behaves correctly
    inside if/else branches without requiring extra braces.
*/
#define CHECK(expr)                                                      \
    do {                                                                 \
        tests_run++;                                                     \
        if (!(expr)) {                                                   \
            tests_failed++;                                              \
            fprintf(stderr, "  FAIL  %s:%d  ->  %s\n",                 \
                    __FILE__, __LINE__, #expr);                          \
        }                                                                \
    } while (0)

/*
    TEST_SUMMARY() — Print results and exit with appropriate code.

    Exit code 0 means all tests passed (Unix convention for success).
    Exit code 1 means at least one test failed.

    The Makefile's test target checks these exit codes to determine
    whether the full test suite passed.
*/
#define TEST_SUMMARY()                                                   \
    do {                                                                 \
        if (tests_failed == 0) {                                         \
            printf("  OK    %d/%d tests passed\n",                      \
                   tests_run, tests_run);                                \
        } else {                                                         \
            printf("  FAIL  %d/%d tests passed (%d failed)\n",          \
                   tests_run - tests_failed, tests_run, tests_failed);   \
        }                                                                \
        return (tests_failed == 0) ? 0 : 1;                             \
    } while (0)

#endif /* TEST_HARNESS_H */
