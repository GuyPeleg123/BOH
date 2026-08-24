/* ppscheck — verify the two B210s share a coherent 1-PPS epoch.
 *
 * Opens both radios (external clock+time), latches each to the next PPS edge via
 * set_time_unknown_pps(0), waits, then reads both device times back-to-back many
 * times. If a single shared 1-PPS is cleanly wired to both, their FRACTIONAL
 * seconds must match to well under 1 ms (they both count from the same PPS edge),
 * and the whole-second difference is a small constant. A large/erratic fractional
 * difference means the PPS is NOT coherently shared — the real blocker for
 * dual-radio UL/DL alignment.
 *
 * Build: gcc scripts/ppscheck.c -o build/ppscheck -luhd
 * Usage: build/ppscheck 32FCD4C 3367EF9
 */
#include <uhd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static uhd_usrp_handle open_ext(const char* serial)
{
    char args[128];
    snprintf(args, sizeof(args), "serial=%s", serial);
    uhd_usrp_handle u;
    if (uhd_usrp_make(&u, args) != UHD_ERROR_NONE) return NULL;
    uhd_usrp_set_clock_source(u, "external", 0);
    uhd_usrp_set_time_source(u, "external", 0);
    return u;
}

int main(int argc, char** argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s <serialA> <serialB>\n", argv[0]); return 2; }
    uhd_usrp_handle a = open_ext(argv[1]);
    uhd_usrp_handle b = open_ext(argv[2]);
    if (!a || !b) { fprintf(stderr, "open failed\n"); return 2; }

    /* small settle for the 10 MHz PLL */
    struct timespec s = {0, 300L*1000000L}; nanosleep(&s, NULL);

    /* Latch both to the next PPS edge, back-to-back (same PPS window). */
    uhd_usrp_set_time_unknown_pps(a, 0, 0.0);
    uhd_usrp_set_time_unknown_pps(b, 0, 0.0);
    struct timespec w = {1, 200L*1000000L}; nanosleep(&w, NULL); /* wait > 1 PPS */

    printf("=== PPS coherence: 10 samples of (A_time, B_time, frac_diff_us) ===\n");
    double max_frac = 0, min_frac = 1e9;
    for (int i = 0; i < 10; i++) {
        int64_t sa=0, sb=0; double fa=0, fb=0;
        uhd_usrp_get_time_now(a, 0, &sa, &fa);
        uhd_usrp_get_time_now(b, 0, &sb, &fb);
        double frac_us = (fa - fb) * 1e6;              /* sub-second skew (the one that matters) */
        double full_us = ((double)(sa-sb) + (fa-fb)) * 1e6;
        printf("  A=%ld.%06.0f  B=%ld.%06.0f  | frac_diff=%.1f us  full_diff=%.1f us  secs_eq=%d\n",
               (long)sa, fa*1e6, (long)sb, fb*1e6, frac_us, full_us, (int)(sa==sb));
        double af = frac_us < 0 ? -frac_us : frac_us;
        if (af > max_frac) max_frac = af;
        if (af < min_frac) min_frac = af;
        struct timespec p = {0, 150L*1000000L}; nanosleep(&p, NULL);
    }
    printf("\nFRACTIONAL (sub-second) skew: min=%.1f us  max=%.1f us\n", min_frac, max_frac);
    if (max_frac < 1000.0)
        printf("VERDICT: PPS COHERENT — both radios latched the same 1-PPS edge (skew < 1 ms).\n"
               "         UL/DL alignment is achievable; the fix is software (epoch/realign).\n");
    else
        printf("VERDICT: PPS *NOT* COHERENT — %.1f us sub-second skew means the shared 1-PPS is not\n"
               "         cleanly reaching/latching both B210s. 10 MHz alone (ref_locked) is NOT enough.\n"
               "         Check the physical 1-PPS distribution to BOTH radios' PPS/TRIG inputs.\n", max_frac);

    uhd_usrp_free(&a); uhd_usrp_free(&b);
    return 0;
}
