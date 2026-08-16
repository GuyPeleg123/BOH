/* multicorr2 — two SEPARATE B210 handles (how LTESniffer really runs them),
 * both PPS-latched to the SAME edge (coordinated set_time_next_pps), then both
 * given a timed stream START at a common absolute time. Dumps per-radio IQ so we
 * can cross-correlate: the peak lag = inter-radio sample offset, and phase drift
 * across the capture = relative frequency error (coherence).
 *
 * Build: gcc scripts/multicorr2.c -o build/multicorr2 -luhd -lm
 * Usage: build/multicorr2 <serialA> <serialB> [freq] [gain] [nsamps]
 */
#include <uhd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>

#define CHK(x) do{ uhd_error _e=(x); if(_e) fprintf(stderr,"UHD err %d line %d\n",_e,__LINE__); }while(0)

static uhd_usrp_handle open_dev(const char* serial,double freq,double gain,double rate){
    char a[128]; snprintf(a,sizeof(a),"serial=%s",serial);
    uhd_usrp_handle u; if(uhd_usrp_make(&u,a)){fprintf(stderr,"open %s failed\n",serial);return NULL;}
    CHK(uhd_usrp_set_clock_source(u,"external",0));
    CHK(uhd_usrp_set_time_source(u,"external",0));
    CHK(uhd_usrp_set_rx_rate(u,rate,0));
    uhd_tune_request_t tr; memset(&tr,0,sizeof(tr));
    tr.target_freq=freq; tr.rf_freq_policy=UHD_TUNE_REQUEST_POLICY_AUTO; tr.dsp_freq_policy=UHD_TUNE_REQUEST_POLICY_AUTO;
    uhd_tune_result_t trr; CHK(uhd_usrp_set_rx_freq(u,&tr,0,&trr));
    CHK(uhd_usrp_set_rx_gain(u,gain,0,""));
    return u;
}

static uhd_rx_streamer_handle mkstream(uhd_usrp_handle u,uhd_rx_metadata_handle* md){
    size_t chans[1]={0};
    uhd_stream_args_t sa; memset(&sa,0,sizeof(sa));
    sa.cpu_format="fc32"; sa.otw_format="sc16"; sa.args=""; sa.channel_list=chans; sa.n_channels=1;
    uhd_rx_streamer_handle rx; CHK(uhd_rx_streamer_make(&rx));
    CHK(uhd_usrp_get_rx_stream(u,&sa,rx));   /* slow USB setup — do BEFORE timing */
    CHK(uhd_rx_metadata_make(md));
    return rx;
}
static void arm(uhd_rx_streamer_handle rx,size_t nsamps,int64_t T){
    uhd_stream_cmd_t cmd; memset(&cmd,0,sizeof(cmd));
    cmd.stream_mode=UHD_STREAM_MODE_NUM_SAMPS_AND_DONE; cmd.num_samps=nsamps; cmd.stream_now=false;
    cmd.time_spec_full_secs=T; cmd.time_spec_frac_secs=0.0;
    CHK(uhd_rx_streamer_issue_stream_cmd(rx,&cmd));
}
static size_t drain(uhd_rx_streamer_handle rx,uhd_rx_metadata_handle md,float* buf,size_t nsamps){
    size_t got=0; int zeros=0;
    while(got<nsamps && zeros<5){
        void* b[1]={ buf+got*2 }; size_t n=0;
        CHK(uhd_rx_streamer_recv(rx,b,nsamps-got,&md,4.0,false,&n));
        if(n==0){ zeros++; continue; }     /* tolerate a startup overflow/gap */
        zeros=0; got+=n;
    }
    return got;
}

/* one worker per radio: drain a pre-armed streamer CONCURRENTLY with the other
 * radio so neither device buffer starves. Streamers are armed (timed START at
 * the common T) in the main thread BEFORE these run, so both begin together. */
typedef struct { uhd_rx_streamer_handle rx; uhd_rx_metadata_handle md; size_t nsamps; float* buf; size_t got; } targ_t;
static void* worker(void* p){
    targ_t* t=(targ_t*)p;
    t->got=drain(t->rx,t->md,t->buf,t->nsamps);
    return NULL;
}

int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: %s serialA serialB [freq] [gain] [nsamps]\n",argv[0]);return 2;}
    double freq=argc>3?atof(argv[3]):1845e6, gain=argc>4?atof(argv[4]):50.0, rate=23.04e6;
    size_t nsamps=argc>5?(size_t)atol(argv[5]):1500000;
    double gainB=argc>6?atof(argv[6]):gain;    /* separate gain for radio B (off-band -> boost) */

    uhd_usrp_handle A=open_dev(argv[1],freq,gain,rate), B=open_dev(argv[2],freq,gainB,rate);
    if(!A||!B) return 2;

    /* coordinated latch: wait for a PPS edge on A, then set BOTH to 0 at the
     * NEXT edge so they share the same epoch (avoids the separate-latch race). */
    int64_t lf; double lfr; CHK(uhd_usrp_get_time_last_pps(A,0,&lf,&lfr));
    int64_t nf=lf; double nfr;
    for(int i=0;i<1200 && nf==lf;i++){ usleep(2000); uhd_usrp_get_time_last_pps(A,0,&nf,&nfr); }
    CHK(uhd_usrp_set_time_next_pps(A,0,0.0,0));
    CHK(uhd_usrp_set_time_next_pps(B,0,0.0,0));
    sleep(2);

    int64_t taf; double tafr; CHK(uhd_usrp_get_time_now(A,0,&taf,&tafr));
    int64_t tbf; double tbfr; CHK(uhd_usrp_get_time_now(B,0,&tbf,&tbfr));
    fprintf(stderr,"epoch check: A_time=%ld.%03.0f  B_time=%ld.%03.0f (equal => same PPS epoch)\n",
            (long)taf,tafr*1e3,(long)tbf,tbfr*1e3);

    float* b0=malloc(nsamps*2*sizeof(float));
    float* b1=malloc(nsamps*2*sizeof(float));
    /* create both streamers (slow USB setup) BEFORE reading the clock... */
    uhd_rx_metadata_handle mdA,mdB;
    uhd_rx_streamer_handle rxA=mkstream(A,&mdA);
    uhd_rx_streamer_handle rxB=mkstream(B,&mdB);
    /* ...now a tight, accurate common start, then concurrent drain */
    CHK(uhd_usrp_get_time_now(A,0,&nf,&nfr));
    int64_t T=nf+1;
    fprintf(stderr,"streamers ready, now=%ld.%03.0f -> common start T=%ld\n",(long)nf,nfr*1e3,(long)T);
    arm(rxA,nsamps,T); arm(rxB,nsamps,T);
    targ_t ta={rxA,mdA,nsamps,b0,0}, tb={rxB,mdB,nsamps,b1,0};
    pthread_t pa,pb;
    pthread_create(&pa,NULL,worker,&ta);
    pthread_create(&pb,NULL,worker,&tb);
    pthread_join(pa,NULL); pthread_join(pb,NULL);
    size_t g0=ta.got, g1=tb.got;

    const char* p0="/home/project44/.claude/jobs/8497227e/tmp/ch0.dat";
    const char* p1="/home/project44/.claude/jobs/8497227e/tmp/ch1.dat";
    FILE*f0=fopen(p0,"wb"); fwrite(b0,sizeof(float),g0*2,f0); fclose(f0);
    FILE*f1=fopen(p1,"wb"); fwrite(b1,sizeof(float),g1*2,f1); fclose(f1);
    printf("A got %zu, B got %zu samples, common start T=%ld @ %.1f MHz\n",g0,g1,(long)T,freq/1e6);
    uhd_usrp_free(&A); uhd_usrp_free(&B);
    return 0;
}
