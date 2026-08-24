/* multicorr — capture two B210s as ONE multi_usrp, both tuned to a common
 * frequency, sample-aligned off the shared PPS, and dump per-channel IQ so we
 * can cross-correlate them (inter-radio sample offset) and measure relative
 * phase drift (frequency coherence). This is exactly how LTESniffer opens the
 * pair, so it tests the REAL UL/DL alignment (not the racy separate-handle path).
 *
 * Build: gcc scripts/multicorr.c -o build/multicorr -luhd -lm
 * Usage: build/multicorr <serialA> <serialB> [freq_hz] [gain] [nsamps]
 */
#include <uhd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define CHK(x) do{ uhd_error _e=(x); if(_e){ fprintf(stderr,"UHD err %d at line %d\n",_e,__LINE__);} }while(0)

int main(int argc, char** argv){
    if(argc<3){ fprintf(stderr,"usage: %s serialA serialB [freq] [gain] [nsamps]\n",argv[0]); return 2; }
    double freq  = argc>3 ? atof(argv[3]) : 1845e6;
    double gain  = argc>4 ? atof(argv[4]) : 40.0;
    size_t nsamps= argc>5 ? (size_t)atol(argv[5]) : 2000000;
    double rate  = 23.04e6;

    char args[256];
    snprintf(args,sizeof(args),"serial0=%s,serial1=%s",argv[1],argv[2]);
    uhd_usrp_handle usrp;
    CHK(uhd_usrp_make(&usrp,args));

    for(size_t m=0;m<2;m++){
        CHK(uhd_usrp_set_clock_source(usrp,"external",m));
        CHK(uhd_usrp_set_time_source(usrp,"external",m));
    }
    uhd_tune_request_t tr; memset(&tr,0,sizeof(tr));
    tr.target_freq=freq; tr.rf_freq_policy=UHD_TUNE_REQUEST_POLICY_AUTO; tr.dsp_freq_policy=UHD_TUNE_REQUEST_POLICY_AUTO;
    uhd_tune_result_t trr;
    for(size_t c=0;c<2;c++){
        CHK(uhd_usrp_set_rx_rate(usrp,rate,c));
        CHK(uhd_usrp_set_rx_freq(usrp,&tr,c,&trr));
        CHK(uhd_usrp_set_rx_gain(usrp,gain,c,""));
    }

    /* synchronous multi-channel PPS latch (both channels, same edge) */
    CHK(uhd_usrp_set_time_unknown_pps(usrp,0,0.0));
    sleep(2);

    size_t chans[2]={0,1};
    uhd_stream_args_t sa; memset(&sa,0,sizeof(sa));
    sa.cpu_format="fc32"; sa.otw_format="sc16"; sa.args=""; sa.channel_list=chans; sa.n_channels=2;
    uhd_rx_streamer_handle rx; CHK(uhd_rx_streamer_make(&rx));
    CHK(uhd_usrp_get_rx_stream(usrp,&sa,rx));
    uhd_rx_metadata_handle md; CHK(uhd_rx_metadata_make(&md));

    int64_t full=0; double frac=0;
    CHK(uhd_usrp_get_time_now(usrp,0,&full,&frac));
    uhd_stream_cmd_t cmd; memset(&cmd,0,sizeof(cmd));
    cmd.stream_mode=UHD_STREAM_MODE_NUM_SAMPS_AND_DONE;
    cmd.num_samps=nsamps; cmd.stream_now=false;
    cmd.time_spec_full_secs=full+1; cmd.time_spec_frac_secs=0.0;
    CHK(uhd_rx_streamer_issue_stream_cmd(rx,&cmd));

    float* b0=malloc(nsamps*2*sizeof(float));
    float* b1=malloc(nsamps*2*sizeof(float));
    size_t got=0;
    while(got<nsamps){
        void* buffs[2]={ b0+got*2, b1+got*2 };
        size_t n=0;
        CHK(uhd_rx_streamer_recv(rx,buffs,nsamps-got,&md,5.0,false,&n));
        uhd_rx_metadata_error_code_t ec=UHD_RX_METADATA_ERROR_CODE_NONE;
        uhd_rx_metadata_error_code(md,&ec);
        if(n==0){ if(ec) fprintf(stderr,"recv stop, err=%d\n",ec); break; }
        got+=n;
    }
    const char* p0="/home/project44/.claude/jobs/8497227e/tmp/ch0.dat";
    const char* p1="/home/project44/.claude/jobs/8497227e/tmp/ch1.dat";
    FILE*f0=fopen(p0,"wb"); fwrite(b0,sizeof(float),got*2,f0); fclose(f0);
    FILE*f1=fopen(p1,"wb"); fwrite(b1,sizeof(float),got*2,f1); fclose(f1);
    printf("captured %zu sample-aligned samples/channel at %.3f MHz gain %.0f\n", got, freq/1e6, gain);
    uhd_usrp_free(&usrp);
    return 0;
}
