//
//  blizzardJailbreak.c
//
//  Created by GeoSn0w on 8/10/20.
//  Copyright © 2020 GeoSn0w. All rights reserved.
//

#include "blizzardJailbreak.h"
#include "../sock_port/exploit.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <mach/mach.h>
#include <sys/mman.h>
mach_port_t tfp0 = 0;

int exploit_init(){
    tfp0 = get_tfp0();
    
    if (MACH_PORT_VALID(tfp0)){
        printf("[+] Successfully got tfp0!\n");
        return 0;
    } else {
        printf("[!] Could not get tfp0!\n");
        return -1;
    }
   
}

int rootifyOurselves(){
    return 0;
}
