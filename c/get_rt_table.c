
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/un.h>

/**

Platform:
    Mac OS X

Note:
    Source Code from book (Unix Network Programming)[http://www.unpbook.com/].
    Author: http://www.masterraghu.com/subjects/np/introduction/
    Read  : http://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch18lev1sec3.html

Build:
    $ cc xnu_get_rt_table.c
    $ ./a.out

**/

// Round up 'a' to next multiple of 'size', which must be a power of 2
#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

// Step to next socket address structure;
// if sa_len is 0, assume it is sizeof(u_long).
#define NEXT_SA(ap) ap = (struct sockaddr *) \
    ((caddr_t) ap + (ap->sa_len ? ROUNDUP(ap->sa_len, sizeof (u_long)) : \
                                    sizeof(u_long)))


void get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info) {
    int     i;
    for (i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            rti_info[i] = sa;
            NEXT_SA(sa);
        } else
            rti_info[i] = NULL;
    }
}


// include sock_ntop
char * sock_ntop(const struct sockaddr *sa, socklen_t salen) {
    char        portstr[8];
    static char str[128];  // Unix domain is largest
    u_char      *ptr;
    struct sockaddr_dl  *sdl;

    switch (sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in  *sin = (struct sockaddr_in *) sa;

        if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL) {
            return(NULL);
        }
        if (ntohs(sin->sin_port) != 0) {
            snprintf(portstr, sizeof(portstr), ":%d", ntohs(sin->sin_port));
            strcat(str, portstr);
        }
        return(str);
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        str[0] = '[';
        if (inet_ntop(AF_INET6, &sin6->sin6_addr, str + 1, sizeof(str) - 1) == NULL)
            return(NULL);
        if (ntohs(sin6->sin6_port) != 0) {
            snprintf(portstr, sizeof(portstr), "]:%d", ntohs(sin6->sin6_port));
            strcat(str, portstr);
            return(str);
        }
        return (str + 1);
    }
    case AF_UNIX: {
        struct sockaddr_un  *unp = (struct sockaddr_un *) sa;

        // OK to have no pathname bound to the socket: happens on
        // every connect() unless client calls bind() first.
        if (unp->sun_path[0] == 0)
            strcpy(str, "(no pathname bound)");
        else
            snprintf(str, sizeof(str), "%s", unp->sun_path);
        return(str);
    }
    case AF_LINK: {
        struct sockaddr_dl  *sdl = (struct sockaddr_dl *) sa;

        if (sdl->sdl_nlen > 0) {
            ptr = (u_char *) &sdl->sdl_data[sdl->sdl_nlen];
            printf("  %x:%x:%x:%x:%x:%x\n", *ptr, *(ptr+1),
                *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
        } else {
            snprintf(str, sizeof(str), "AF_LINK#%d", sdl->sdl_index);
        }
        return(str);
    }
    default:
        // snprintf(str, sizeof(str), "sock_ntop: unknown AF_XXX: %d, len %d",
        //              sa->sa_family, salen);
        return(str);
    }
    return (NULL);
}

char * net_rt_dump(int family, int flags, size_t *lenp) {
    int     mib[6];
    char    *buf;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = family; // only addresses of this family
    mib[4] = NET_RT_DUMP;
    mib[5] = flags;  // not looked at with NET_RT_DUMP
    if (sysctl(mib, 6, NULL, lenp, NULL, 0) < 0)
        return(NULL);

    if ( (buf = malloc(*lenp)) == NULL)
        return(NULL);
    if (sysctl(mib, 6, buf, lenp, NULL, 0) < 0)
        return(NULL);

    return(buf);
}

void pr_rtable(int family) {
    char                *buf, *next, *lim;
    size_t              len;
    struct rt_msghdr    *rtm;
    struct sockaddr     *sa, *rti_info[RTAX_MAX];

    buf = net_rt_dump(family, 0, &len);

    if ( buf == NULL ) {
        printf("net_rt_dump error\n");
    } else {
        lim = buf + len;
        for (next = buf; next < lim; next += rtm->rtm_msglen) {
            rtm = (struct rt_msghdr *) next;
            sa = (struct sockaddr *)(rtm + 1);
            get_rtaddrs(rtm->rtm_addrs, sa, rti_info);
            if ( (sa = rti_info[RTAX_DST]) != NULL)
                printf("dest: %s", sock_ntop(sa, sa->sa_len));

            if ( (sa = rti_info[RTAX_GATEWAY]) != NULL)
                printf(", gateway: %s", sock_ntop(sa, sa->sa_len));
            printf("\n");
        }
    }
}

int main(int argc, char **argv) {
    int family;
    // family = AF_INET;  // inet4
    // family = AF_INET6; // inet6
    // family = 0;        // inet4 & inet6
    family = 0;
    pr_rtable(family);
    exit(0);
}
