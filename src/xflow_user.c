/* SPDX-License-Identifier: GPL-2->0 */

/* NOTE:
 * We have used the veth index as primary key for this Poc, a more realistic
 * implementation should use the inner ip as the primary key instead*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <math.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>


#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>


#include "../common/common_user_bpf_xdp.h"
#include "../common/common_params.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/common_defines.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

void  print_usage(){
  printf("./xflow_user -t <format type> -w <output file>\n");
}


// static const struct option long_options[] = {
//         {"vlid", required_argument,       0,  'v' },
//         {"operation", required_argument,       0,  'o' },
//         //"Geneve tunnel vlan id of <connection>", "<vlid>", true },
//         {"flags", required_argument,       0,  'f' },
//         //"Geneve tunnel flags of <connection>", "<flags>", true },
//         {"s_port",    required_argument, 0,  'p' },
//         //"Source Port of <connection>", "<port>", true },
//         {"iface",   required_argument, 0,  'i' },
//         //"Iface index redirect <dev>[NOT enabled]", "<ifidx>", true },
//         {"c_iface",      required_argument,       0,  'c' },
//         //"Iface index capture <dev>", "<ifidx>", true },
//         {"s_ip_addr", required_argument,       NULL,  's' },
//         //"Source IP address of <dev>", "<ip>", true },
//         {"d_ip_addr",    required_argument, NULL,  'd' },
//         //"Destination IP address of <redirect-dev>", "<ip>", true },
//         {"s_mac",   required_argument, NULL,  'e' },
//         //"Source MAC address of <dev>", "<mac>", true },
//         {"d_mac",   required_argument, NULL,  't' },
//         //"Destination MAC address of <redirect-dev>", "<mac>", true },
// 	{0,           0, NULL,  0   }
//     };

// int parse_params(int argc, char *argv[]) {
//     int opt= 0;
//     int long_index =0;

//     while ((opt = getopt_long(argc, argv,"v:f:p:i:c:s:d:e:t:o:", 
//                    long_options, &long_index )) != -1) {
//       printf("opt: %c arg: %s \n",opt,optarg);
//       switch (opt) {
//              case 'v' : vlid = atoi(optarg);
//                  break;
//              case 'f' : flags = atoi(optarg);
//                  break;
//              case 'p' : s_port = atoi(optarg); 
//                  break;
//              case 'i' : iface = atoi(optarg);
//                  break;
//              case 'c' : c_iface = atoi(optarg);
//                  break;
// 	     case 's' : strncpy(s_addr,optarg,16);
//                  break;
//              case 'd' : strncpy(d_addr,optarg,16);
//                  break;
//              case 'e' : strncpy(s_mac,optarg,18);
//                  break;
//              case 't' : strncpy(d_mac,optarg,18);
//                  break;
// 		case 'o' : if(strcmp(optarg,"ADD")==0) is_add = 1;
// 			   else if(strcmp(optarg,"DEL")==0) is_add = 0;
// 			   else{
// 			     printf("INVALID OPt\n");
// 			     print_usage();
// 			     exit(EXIT_FAILURE);
// 			     }
// 		  break;
//              default: print_usage(); 
//                  exit(EXIT_FAILURE);
//         }
//     }
//     if(is_add==1 && (vlid==-1 || flags==-1 || iface==-1 || c_iface==-1 || s_addr[0]=='\0' || d_addr[0]=='\0' || d_mac[0] == '\0' || s_mac[0] == '\0')){
//       print_usage();
//       return -1;
//     }else if(iface==-1){
// 	    print_usage();
// 	    return 1;
//     }
//        return 0;
// }

const char *pin_base_dir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	
	int map_fd;
	uint32_t key = 0;
	uint32_t next_key;
	flow_map my_flow_map;
	
	// if(parse_params(argc,argv)!=0){
	// 	fprintf(stderr, "ERR: parsing params\n");
	// 	return EXIT_FAIL_OPTION;
	// }

	/* Open the map for geneve config */
	map_fd = open_bpf_map_file(pin_base_dir, "xflow_map", NULL);
	if (map_fd < 0) {
	  	fprintf(stderr,"ERR: opening map\n");
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s \n", pin_base_dir);

	/* Get the flow_maps iteratively using bpf_map_get_next_key()

	while (bpf_map_get_next_key(map_fd, const void *key, void *next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &my_flow_map);
		dump_flow_map(my_flow_map);
		key = next_key;
	}
	*/
	return EXIT_OK;
}
