// pps_hw — precise 1 Hz PPS on GPIO18 for the USRP PPS-IN (Pi 2 / BCM2836).
//
// Replaces the old pps.sh, which bit-banged GPIO18 from a bash loop:
//     pinctrl set 18 dh; sleep 0.1; pinctrl set 18 dl; sleep 0.9
// Each iteration forked TWO pinctrl processes (~20 ms each) ON TOP of the 1.0 s
// of sleeps, so the real period was ~1.04 s, not 1.000 s — and it drifted freely.
// Two USRPs latching different pulses of that train ended up ~1.04 s apart
// (measured: constant ~39.8 ms sub-second skew), which left the dual-radio
// sniffer with no common time epoch and a random UL/DL sample offset per run.
//
// This version:
//   * writes GPIO18 by direct register poke (GPSET/GPCLR) — no fork, ~microsecond
//   * schedules every edge from a FIXED epoch with clock_nanosleep(TIMER_ABSTIME)
//     on CLOCK_REALTIME, so period error NEVER accumulates (self-correcting)
//   * aligns the rising edge to the exact top of each UTC second
//   * optional fixed offset (--offset-us) to trim residual cable/latch skew
//
// Build: gcc -O2 -o pps_hw pps_hw.c
// Run:   sudo ./pps_hw [--offset-us N] [--high-ms N]
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>

#define PERI_BASE 0x3F000000u              // Pi 2 / BCM2836
#define GPIO_BASE (PERI_BASE + 0x200000u)
#define GPSET0    (0x1C/4)
#define GPCLR0    (0x28/4)
#define PPS_PIN   18

static volatile uint32_t *map_peri(uint32_t base) {
  int fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (fd < 0) { perror("open /dev/mem (need root)"); exit(1); }
  void *m = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, base);
  close(fd);
  if (m == MAP_FAILED) { perror("mmap"); exit(1); }
  return (volatile uint32_t*)m;
}

int main(int argc, char **argv) {
  long offset_us = 0, high_ms = 100;
  for (int i = 1; i < argc - 1; i++) {
    if (!strcmp(argv[i], "--offset-us")) offset_us = strtol(argv[i+1], 0, 10);
    if (!strcmp(argv[i], "--high-ms"))   high_ms   = strtol(argv[i+1], 0, 10);
  }

  volatile uint32_t *gpio = map_peri(GPIO_BASE);
  // GPIO18 -> output. FSEL18 = bits 24..26 of GPFSEL1; output = 0b001.
  gpio[1] = (gpio[1] & ~(7u<<24)) | (1u<<24);
  gpio[GPCLR0] = (1u << PPS_PIN);          // start low

  // Real-time priority + lock memory: keep the scheduler off our edges.
  struct sched_param sp; sp.sched_priority = 99;
  if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0) perror("sched_setscheduler (continuing)");
  if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)     perror("mlockall (continuing)");

  struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
  struct timespec t = { now.tv_sec + 2, 0 };        // first edge: next whole second +2
  fprintf(stderr, "[pps_hw] GPIO%d, 1.000000 s period, high=%ld ms, offset=%ld us, "
                  "first rising edge at %ld.000000\n", PPS_PIN, high_ms, offset_us, (long)t.tv_sec);

  const long NS = 1000000000L;
  for (;;) {
    // ---- rising edge, at the exact top of the second (+ trim offset) ----
    struct timespec up = t;
    long off_ns = offset_us * 1000L;
    up.tv_nsec += off_ns;
    while (up.tv_nsec >= NS) { up.tv_nsec -= NS; up.tv_sec++; }
    while (up.tv_nsec < 0)   { up.tv_nsec += NS; up.tv_sec--; }
    clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &up, NULL);
    gpio[GPSET0] = (1u << PPS_PIN);

    // ---- falling edge, high_ms later ----
    struct timespec dn = up;
    dn.tv_nsec += high_ms * 1000000L;
    while (dn.tv_nsec >= NS) { dn.tv_nsec -= NS; dn.tv_sec++; }
    clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &dn, NULL);
    gpio[GPCLR0] = (1u << PPS_PIN);

    // Next second, computed from the FIXED epoch -> no accumulated drift.
    t.tv_sec += 1;
  }
  return 0;
}
