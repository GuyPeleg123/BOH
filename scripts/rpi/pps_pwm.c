/* pps_pwm — hardware, phase-locked 1 Hz PPS on GPIO18 (PWM0) for the USRP PPS-IN.
 *
 * Replaces the software-timed pps_hw (GPIO18 register-poke loop), whose pulse
 * timing was set by the Linux scheduler and was NOT phase-locked to the 10 MHz
 * (GPCLK0). That made each B210 latch the PPS at a random 10 MHz phase, so the
 * two radios' sample alignment jittered ~a cyclic-prefix run-to-run.
 *
 * This drives GPIO18 with the HARDWARE PWM0 peripheral, clocked from the SAME
 * PLLD source as GPCLK0 (SRC=6). PWM clock = PLLD/divi (default divi=50 => the
 * same 10 MHz as GPCLK0). PWM range = pwm_clk cycles => exactly 1 Hz. Mark/space
 * mode gives a clean pulse (default 100 ms high). Because the PWM and GPCLK0
 * share PLLD and free-run together, the PPS-to-10MHz phase is FIXED and jitter-
 * free -> both B210s latch the same 10 MHz cycle every second (coherent).
 *
 * Pi 2 / BCM2836. Build:  gcc -O2 -o pps_pwm pps_pwm.c
 * Run (root):  sudo ./pps_pwm [clk_divi=50] [high_ms=100]
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define PERI_BASE   0x3F000000u          /* Pi 2 / BCM2836 */
#define GPIO_BASE   (PERI_BASE + 0x200000u)
#define CM_BASE     (PERI_BASE + 0x101000u)
#define PWM_BASE    (PERI_BASE + 0x20C000u)
#define CM_PWMCTL   (0xA0/4)
#define CM_PWMDIV   (0xA4/4)
#define CM_PASSWD   0x5A000000u
#define CM_ENAB     (1u<<4)
#define CM_BUSY     (1u<<7)
#define SRC_PLLD    6u                    /* same source GPCLK0 uses */
#define PWM_CTL     (0x00/4)
#define PWM_STA     (0x04/4)
#define PWM_RNG1    (0x10/4)
#define PWM_DAT1    (0x14/4)
#define PWEN1       (1u<<0)               /* enable channel 1 */
#define MSEN1       (1u<<7)               /* mark/space mode => clean pulse */

static volatile uint32_t *map_peri(uint32_t base){
    int fd = open("/dev/mem", O_RDWR|O_SYNC);
    if(fd<0){ perror("open /dev/mem (need root)"); exit(1); }
    void *m = mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,base);
    close(fd);
    if(m==MAP_FAILED){ perror("mmap"); exit(1); }
    return (volatile uint32_t*)m;
}

int main(int argc,char**argv){
    uint32_t divi    = (argc>1)?(uint32_t)strtoul(argv[1],0,0):50;   /* PLLD/50 = 10 MHz (== GPCLK0) */
    uint32_t high_ms = (argc>2)?(uint32_t)strtoul(argv[2],0,0):100;
    if(divi<2||divi>4095){ fprintf(stderr,"divi 2..4095\n"); return 1; }

    /* PWM clock = PLLD/divi; GPCLK0 (PLLD/50) is empirically 10 MHz => PLLD~500 MHz.
     * rng = one second of PWM-clock cycles = PWM clock rate in Hz. */
    double pwm_clk = 500e6/(double)divi;          /* = 10 MHz at divi=50 */
    uint32_t rng = (uint32_t)(pwm_clk + 0.5);     /* cycles per 1 s => 1 Hz */
    uint32_t dat = (uint32_t)(pwm_clk*high_ms/1000.0 + 0.5);

    volatile uint32_t *gpio=map_peri(GPIO_BASE), *cm=map_peri(CM_BASE), *pwm=map_peri(PWM_BASE);

    /* GPIO18 -> ALT5 (PWM0): GPFSEL1, pin 18 field bits [26:24], ALT5 code = 2 */
    gpio[1] = (gpio[1] & ~(7u<<24)) | (2u<<24);

    /* stop the PWM clock, set source PLLD + divisor, re-enable */
    cm[CM_PWMCTL] = CM_PASSWD | (cm[CM_PWMCTL] & ~CM_ENAB);
    while(cm[CM_PWMCTL] & CM_BUSY){ }
    cm[CM_PWMDIV] = CM_PASSWD | (divi<<12);
    cm[CM_PWMCTL] = CM_PASSWD | SRC_PLLD;
    cm[CM_PWMCTL] = CM_PASSWD | SRC_PLLD | CM_ENAB;
    while(!(cm[CM_PWMCTL] & CM_BUSY)){ }

    /* configure PWM0 channel 1: mark/space, 1 s period, high for high_ms */
    pwm[PWM_CTL] = 0;
    usleep(1000);
    pwm[PWM_RNG1] = rng;
    pwm[PWM_DAT1] = dat;
    pwm[PWM_CTL]  = MSEN1 | PWEN1;

    printf("PWM PPS on GPIO18: clk=PLLD/%u=%.4f MHz  RNG=%u (=> %.6f Hz)  high=%u ms\n",
           divi, pwm_clk/1e6, rng, pwm_clk/(double)rng, high_ms);
    printf("hardware-timed + phase-locked to the 10 MHz (GPCLK0).\n");
    fflush(stdout);
    /* The PWM peripheral is autonomous, but stay resident so systemd sees an
       active (Type=simple) service and so `pkill -f pps_hw` / `stop` can end it. */
    for(;;) pause();
    return 0;
}
