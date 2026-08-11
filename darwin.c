#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcp_monitor.skel.h"

#define TCP_CA_NAME_MAX 16
#define MAX_CCAS 16
#define MB_DIVISOR 1048576.0
#define SOCK_HASH_SIZE 2048

/* Identifies an active IPv4 connection using a standard 4-tuple key. */
struct conn_key {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
};

/* Aggregates socket telemetry extracted from the eBPF kernel map. */
struct conn_val {
    char cca[TCP_CA_NAME_MAX];
    uint64_t bytes_sent;
    uint32_t srtt_us;
    uint32_t min_rtt_us;
};

/* Tracks cumulative and exponentially smoothed performance metrics per CCA module. */
struct cca_stats {
    char name[TCP_CA_NAME_MAX];
    double ema_speed_mbps;
    double ema_srtt_ms;
    double ema_min_rtt_ms;
    double ema_ratio; 
    double utility; 
    uint64_t total_bytes;
    int chosen_count;
    bool active;
};
struct cca_stats cca_groups[MAX_CCAS];

/* Local cache entry for tracking per-socket byte differentials between sampling ticks. */
struct sock_state {
    struct conn_key key;
    uint64_t prev_bytes;
    bool in_use;
    bool seen_this_tick; 
};
struct sock_state sock_cache[SOCK_HASH_SIZE];

/* Signal and global connection counters */
static volatile bool exiting = false;
uint64_t total_sockets_opened = 0; 
int sockets_since_last_switch = 0; 

/* Registered kernel congestion control modules */
char available_ccas[MAX_CCAS][TCP_CA_NAME_MAX];
int num_available_ccas = 0;
int current_cca_index = 0;

/* Management/Local IP address excluded from metric calculations */
const char *unwantedIp = "192.168.122.1";

/* Utility score weighting parameters and iteration bounds loaded from configuration */
int wTempo = 50;
int wVazao = 50;
int numVezes = 5;

double global_max_speed_mbps = 0.0;

/* Controller state machine phases for dynamic switching strategy */
enum ControllerPhase {
    PHASE_INIT,     /* Initial baseline sampling across all available CCAs */
    PHASE_EXPLORE,  /* Utility-weighted probabilistic evaluation */
    PHASE_EXPLOIT   /* Lock-in execution on the highest-utility CCA */
} current_phase = PHASE_INIT;

int init_index = 0;

static void sig_handler(int sig) { exiting = true; }

/* Simple XOR hash function mapping connection 4-tuple to local tracking cache */
uint32_t hash_key(struct conn_key *k) {
    return (k->saddr ^ k->daddr ^ k->sport ^ k->dport) % SOCK_HASH_SIZE;
}

/* Returns array index for a given CCA name, registering it if not previously seen */
int get_cca_index(const char *name) {
    for (int i = 0; i < MAX_CCAS; i++) {
        if (cca_groups[i].active && strcmp(cca_groups[i].name, name) == 0) return i;
        if (!cca_groups[i].active) {
            strncpy(cca_groups[i].name, name, TCP_CA_NAME_MAX);
            cca_groups[i].active = true;
            return i;
        }
    }
    return 0; 
}

/* Parses controller weights and selection limits from local configuration file */
void load_weights() {
    FILE *fp = fopen("razaoD", "r");
    if (fp) {
        char line[64];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "tempo:", 6) == 0) {
                wTempo = atoi(line + 6);
            } else if (strncmp(line, "vazao:", 6) == 0) {
                wVazao = atoi(line + 6);
            } else if (strncmp(line, "numVezes:", 9) == 0) {
                numVezes = atoi(line + 9);
            }
        }
        fclose(fp);
    } else {
        printf("Warning: Could not open 'razaoD', using default parameters.\n");
    }
}

/* Reads active TCP congestion control algorithms enabled in sysctl */
void load_available_ccas() {
    FILE *fp = fopen("/proc/sys/net/ipv4/tcp_available_congestion_control", "r");
    if (fp) {
        char ccas[256];
        if (fgets(ccas, sizeof(ccas), fp)) {
            ccas[strcspn(ccas, "\n")] = 0;
            char *token = strtok(ccas, " ");
            while (token != NULL && num_available_ccas < MAX_CCAS) {
                strncpy(available_ccas[num_available_ccas], token, TCP_CA_NAME_MAX);
                num_available_ccas++;
                token = strtok(NULL, " ");
            }
        }
        fclose(fp);
    }
}

/* Sets default system-wide TCP congestion control algorithm via procfs */
void set_system_cca(const char *cca_name) {
    FILE *fp = fopen("/proc/sys/net/ipv4/tcp_congestion_control", "w");
    if (fp) {
        fprintf(fp, "%s", cca_name);
        fclose(fp);
    }
}

/* Identifies the registered CCA exhibiting the highest calculated utility */
int get_best_cca_index() {
    int best_idx = 0;
    double max_util = -1.0;
    for (int i = 0; i < num_available_ccas; i++) {
        int c_idx = get_cca_index(available_ccas[i]);
        if (cca_groups[c_idx].utility > max_util) {
            max_util = cca_groups[c_idx].utility;
            best_idx = i;
        }
    }
    return best_idx;
}

/* 
 * Selects candidate CCA using a weighted random policy (13/16 chance for top performer, 
 * 3/16 split among remaining options), excluding algorithms that reached selection bounds.
 */
int select_next_cca_by_utility() {
    int eligible_ranks[MAX_CCAS];
    int num_eligible = 0;

    /* Filter algorithms that have not reached the maximum evaluation count */
    for (int i = 0; i < num_available_ccas; i++) {
        int c_idx = get_cca_index(available_ccas[i]);
        if (cca_groups[c_idx].chosen_count < numVezes) {
            eligible_ranks[num_eligible] = i;
            num_eligible++;
        }
    }

    /* Fallback strategies if standard candidate pool is insufficient */
    if (num_eligible == 0) return get_best_cca_index(); 
    if (num_eligible == 1) return eligible_ranks[0];

    /* Rank eligible algorithms by utility score in descending order */
    for (int i = 0; i < num_eligible - 1; i++) {
        for (int j = i + 1; j < num_eligible; j++) {
            double u_i = cca_groups[get_cca_index(available_ccas[eligible_ranks[i]])].utility;
            double u_j = cca_groups[get_cca_index(available_ccas[eligible_ranks[j]])].utility;
            if (u_j > u_i) {
                int temp = eligible_ranks[i];
                eligible_ranks[i] = eligible_ranks[j];
                eligible_ranks[j] = temp;
            }
        }
    }

    double r = (double)rand() / RAND_MAX;
    
    /* Assign ~81.25% probability weight to the highest utility eligible CCA */
    if (r <= (13.0 / 16.0)) {
        return eligible_ranks[0];
    } 
    /* Distribute remaining ~18.75% probability uniformly among secondary candidates */
    else {
        int remaining_ccas = num_eligible - 1;
        double slice_per_cca = (3.0 / 16.0) / remaining_ccas;
        
        double adjusted_r = r - (13.0 / 16.0); 
        int selected_offset = (int)(adjusted_r / slice_per_cca);
        
        if (selected_offset >= remaining_ccas) {
            selected_offset = remaining_ccas - 1;
        }
        
        return eligible_ranks[1 + selected_offset]; 
    }
}

int main(int argc, char **argv)
{
    struct tcp_monitor_bpf *skel;
    int err, map_fd;
    
    srand(time(NULL)); 
    signal(SIGINT, sig_handler);
    memset(cca_groups, 0, sizeof(cca_groups));
    memset(sock_cache, 0, sizeof(sock_cache));

    load_weights(); 
    load_available_ccas();
    
    if (num_available_ccas > 0) {
        current_cca_index = 0;
        set_system_cca(available_ccas[current_cca_index]);
        cca_groups[get_cca_index(available_ccas[current_cca_index])].chosen_count = 1;
    }

    skel = tcp_monitor_bpf__open_and_load();
    if (!skel) return 1;

    err = tcp_monitor_bpf__attach(skel);
    if (err) goto cleanup;

    map_fd = bpf_map__fd(skel->maps.active_conns);
    uint32_t ignore_ip_num = inet_addr(unwantedIp);

    /* Main polling and switching control loop (~4 Hz frequency) */
    while (!exiting) {

        struct conn_key lookup_key = {}, next_key;
        struct conn_val val;

        double tick_speed_mbps[MAX_CCAS] = {0};
        double tick_srtt_sum[MAX_CCAS] = {0};
        double tick_min_rtt_sum[MAX_CCAS] = {0};
        double tick_ratio_sum[MAX_CCAS] = {0}; 
        int active_sock_count[MAX_CCAS] = {0};

        for (int i = 0; i < SOCK_HASH_SIZE; i++) sock_cache[i].seen_this_tick = false;

        /* Iterate through active eBPF connections map */
        while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key) == 0) {
            
            /* Ignore management IP address activity */
            if (next_key.saddr == ignore_ip_num || next_key.daddr == ignore_ip_num) {
                lookup_key = next_key;
                continue; 
            }

            if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
                
                uint32_t h = hash_key(&next_key);
                while (sock_cache[h].in_use && memcmp(&sock_cache[h].key, &next_key, sizeof(next_key)) != 0) {
                    h = (h + 1) % SOCK_HASH_SIZE;
                }

                uint64_t delta_bytes = 0;
                if (sock_cache[h].in_use) {
                    if (val.bytes_sent >= sock_cache[h].prev_bytes)
                        delta_bytes = val.bytes_sent - sock_cache[h].prev_bytes;
                } else {
                    sock_cache[h].key = next_key;
                    sock_cache[h].in_use = true;
                    delta_bytes = val.bytes_sent;
                    total_sockets_opened++;
                    sockets_since_last_switch++;
                    
                    /* Evaluate state transitions upon socket threshold */
                    if (sockets_since_last_switch >= 9 && num_available_ccas > 0) {
                        
                        if (current_phase == PHASE_INIT) {
                            init_index++;
                            if (init_index >= num_available_ccas) {
                                current_phase = PHASE_EXPLORE;
                                current_cca_index = select_next_cca_by_utility(); 
                            } else {
                                current_cca_index = init_index; 
                            }
                            
                            set_system_cca(available_ccas[current_cca_index]);
                            cca_groups[get_cca_index(available_ccas[current_cca_index])].chosen_count++;
                            sockets_since_last_switch = 0; 
                            
                        } else if (current_phase == PHASE_EXPLORE) {
                            
                            /* Check if all algorithms have completed evaluation bounds */
                            int done_count = 0;
                            for (int i = 0; i < num_available_ccas; i++) {
                                if (cca_groups[get_cca_index(available_ccas[i])].chosen_count >= numVezes) {
                                    done_count++;
                                }
                            }

                            if (done_count == num_available_ccas) {
                                current_phase = PHASE_EXPLOIT;
                                current_cca_index = get_best_cca_index();
                                set_system_cca(available_ccas[current_cca_index]);
                                sockets_since_last_switch = 0;
                            } else {
                                current_cca_index = select_next_cca_by_utility();
                                set_system_cca(available_ccas[current_cca_index]);
                                cca_groups[get_cca_index(available_ccas[current_cca_index])].chosen_count++;
                                sockets_since_last_switch = 0; 
                            }
                            
                        } else if (current_phase == PHASE_EXPLOIT) {
                            /* Maintain optimal selection state and reset switch counter */
                            sockets_since_last_switch = 0;
                        }
                    }
                }
                
                sock_cache[h].prev_bytes = val.bytes_sent; 
                sock_cache[h].seen_this_tick = true; 

                int c_idx = get_cca_index(val.cca);
                cca_groups[c_idx].total_bytes += delta_bytes;

                if (delta_bytes > 0) {
                    double sock_speed_mbps = ((double)delta_bytes * 7.8125) / MB_DIVISOR;
                    tick_speed_mbps[c_idx] += sock_speed_mbps;
                    tick_srtt_sum[c_idx] += val.srtt_us;
                    tick_min_rtt_sum[c_idx] += val.min_rtt_us;

                    double sock_ratio = (val.srtt_us > 0) ? ((double)val.min_rtt_us / val.srtt_us) : 0.0;
                    tick_ratio_sum[c_idx] += sock_ratio;

                    active_sock_count[c_idx]++;
                }
            }
            lookup_key = next_key;
        }

        /* Garbage collect stale socket tracking entries */
        for (int i = 0; i < SOCK_HASH_SIZE; i++) {
            if (sock_cache[i].in_use && !sock_cache[i].seen_this_tick) sock_cache[i].in_use = false;
        }

        /* Update Exponential Moving Averages (EMA factor alpha = 0.125) */
        for (int i = 0; i < MAX_CCAS; i++) {
            if (cca_groups[i].active) {
                if (active_sock_count[i] > 0) {
                    double avg_tick_speed = tick_speed_mbps[i] / active_sock_count[i];
                    double avg_tick_srtt = (tick_srtt_sum[i] / active_sock_count[i]) / 1000.0;
                    double avg_tick_min_rtt = (tick_min_rtt_sum[i] / active_sock_count[i]) / 1000.0;
                    double avg_tick_ratio = tick_ratio_sum[i] / active_sock_count[i]; 
                    
                    if (cca_groups[i].ema_speed_mbps == 0.0) {
                        cca_groups[i].ema_speed_mbps = avg_tick_speed;
                        cca_groups[i].ema_srtt_ms = avg_tick_srtt;
                        cca_groups[i].ema_min_rtt_ms = avg_tick_min_rtt;
                        cca_groups[i].ema_ratio = avg_tick_ratio;
                    } else {
                        cca_groups[i].ema_speed_mbps = ((7.0 * cca_groups[i].ema_speed_mbps) + avg_tick_speed) / 8.0;
                        cca_groups[i].ema_srtt_ms = ((7.0 * cca_groups[i].ema_srtt_ms) + avg_tick_srtt) / 8.0;
                        cca_groups[i].ema_min_rtt_ms = ((7.0 * cca_groups[i].ema_min_rtt_ms) + avg_tick_min_rtt) / 8.0;
                        cca_groups[i].ema_ratio = ((7.0 * cca_groups[i].ema_ratio) + avg_tick_ratio) / 8.0; 
                    }
                }

                if (cca_groups[i].ema_speed_mbps > global_max_speed_mbps) {
                    global_max_speed_mbps = cca_groups[i].ema_speed_mbps;
                }
            }
        }

        /* Terminal dashboard rendering */
        printf("\033[H\033[J");
        printf("Reinforcement CCA Controller (4 Hz)\n");
        printf("==========================================\n");
        
        const char *phase_str = "";
        if (current_phase == PHASE_INIT) phase_str = "INIT (Establishing Baselines)";
        else if (current_phase == PHASE_EXPLORE) phase_str = "EXPLORE (Utility Weighted Evaluation)";
        else phase_str = "EXPLOIT (Locked on Best CCA)";

        printf("  Controller Phase : [%s]\n", phase_str);
        printf("System Default CCA : [%s]\n", available_ccas[current_cca_index]);
        printf("    Weights Loaded : wTempo=%d, wVazao=%d, numVezes=%d\n", wTempo, wVazao, numVezes);
        printf("  Global Max Speed : %.2f MB/s\n", global_max_speed_mbps); 
        printf(" Total New Sockets : %llu\n", (unsigned long long)total_sockets_opened);
        
        if (current_phase != PHASE_EXPLOIT) {
            printf("    Next Switch In : %d socket(s)\n\n", 10 - sockets_since_last_switch);
        } else {
            printf("    Next Switch In : [LOCKED]\n\n");
        }
        
        printf("%-12s %-8s %-12s %-15s %-12s %-12s %-12s %-12s\n", 
               "ALGORITHM", "CHOSEN", "DATA (MB)", "SPEED (MB/s)", "sRTT (ms)", "minRTT (ms)", "RATIO", "UTILITY");
        printf("--------------------------------------------------------------------------------------------------\n");

        /* Calculate final normalized utility scores and display performance matrix */
        for (int i = 0; i < MAX_CCAS; i++) {
            if (cca_groups[i].active) {
                
                double normalized_speed = 0.0;
                if (global_max_speed_mbps > 0.0) {
                    normalized_speed = cca_groups[i].ema_speed_mbps / global_max_speed_mbps;
                }

                cca_groups[i].utility = (2 * wVazao * normalized_speed) + (wTempo * cca_groups[i].ema_ratio);

                double total_mb = (double)cca_groups[i].total_bytes / MB_DIVISOR;

                printf("%-12s %-8d %-12.2f %-15.2f %-12.2f %-12.2f %-12.2f %-12.2f\n", 
                       cca_groups[i].name, 
                       cca_groups[i].chosen_count,
                       total_mb, 
                       cca_groups[i].ema_speed_mbps,
                       cca_groups[i].ema_srtt_ms,
                       cca_groups[i].ema_min_rtt_ms,
                       cca_groups[i].ema_ratio,
                       cca_groups[i].utility);
            }
        }

        usleep(256000);
    }

cleanup:
    tcp_monitor_bpf__destroy(skel);
    return 0;
}




