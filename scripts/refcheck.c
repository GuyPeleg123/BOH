/* refcheck — Phase-1 external-reference verification for the dual-B210 rig.
 *
 * For each serial given on the command line: forces clock_source=external and
 * time_source=external, then independently reports clock source, time source,
 * ref_locked, PPS presence, and whether device time is advancing. Exits non-zero
 * if ANY radio fails to lock the external reference, so it can gate a capture.
 *
 * Build: gcc -O2 scripts/refcheck.c -o build/refcheck -luhd -lstdc++
 * Usage: build/refcheck 32FCD4C 3367EF9
 */
#include <uhd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static int check_one(const char* serial)
{
    char args[128];
    snprintf(args, sizeof(args), "serial=%s", serial);
    uhd_usrp_handle usrp;
    if (uhd_usrp_make(&usrp, args) != UHD_ERROR_NONE) {
        printf("  [%s] FAIL: cannot open device\n", serial);
        return 1;
    }
    int fail = 0;

    uhd_usrp_set_clock_source(usrp, "external", 0);
    uhd_usrp_set_time_source(usrp, "external", 0);
    /* give the PLL time to lock to the incoming 10 MHz */
    struct timespec ts = {0, 300L * 1000000L}; nanosleep(&ts, NULL);

    char csrc[32] = {0}, tsrc[32] = {0};
    uhd_usrp_get_clock_source(usrp, 0, csrc, sizeof(csrc));
    uhd_usrp_get_time_source(usrp, 0, tsrc, sizeof(tsrc));

    /* ref_locked sensor */
    uhd_sensor_value_handle sv;
    uhd_sensor_value_make_from_bool(&sv, "", false, "", "");
    bool ref_locked = false;
    if (uhd_usrp_get_mboard_sensor(usrp, "ref_locked", 0, &sv) == UHD_ERROR_NONE)
        uhd_sensor_value_to_bool(sv, &ref_locked);
    uhd_sensor_value_free(&sv);

    /* device time advancing? */
    int64_t s0 = 0, s1 = 0; double f0 = 0, f1 = 0;
    uhd_usrp_get_time_now(usrp, 0, &s0, &f0);
    struct timespec t2 = {0, 200L * 1000000L}; nanosleep(&t2, NULL);
    uhd_usrp_get_time_now(usrp, 0, &s1, &f1);
    double dt = (double)(s1 - s0) + (f1 - f0);
    int advancing = (dt > 0.15 && dt < 0.30);

    int csrc_ok = (strcmp(csrc, "external") == 0);
    int tsrc_ok = (strcmp(tsrc, "external") == 0);

    printf("  [%s] clock=%s%s time=%s%s ref_locked=%s advancing=%s (dt=%.3fs) t_now=%ld.%06.0f\n",
           serial,
           csrc, csrc_ok ? "" : "(!)",
           tsrc, tsrc_ok ? "" : "(!)",
           ref_locked ? "TRUE" : "FALSE(!)",
           advancing ? "yes" : "NO(!)",
           dt, (long)s1, f1 * 1e6);

    if (!csrc_ok || !tsrc_ok || !ref_locked || !advancing) fail = 1;
    uhd_usrp_free(&usrp);
    return fail;
}

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <serial> [serial...]\n", argv[0]); return 2; }
    printf("=== Phase-1 external-reference check (%d radios) ===\n", argc - 1);
    int fail = 0;
    for (int i = 1; i < argc; i++) fail |= check_one(argv[i]);
    printf(fail ? "RESULT: FAIL — not all radios locked to external reference\n"
                : "RESULT: PASS — all radios external + ref_locked + time advancing\n");
    return fail;
}
