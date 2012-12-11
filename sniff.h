/*
 * Function prototypes.
 */
extern char *if_getname (void);
extern int if_setname (const char *);
extern void if_close_net (int);
extern void if_open_net (int);
extern void if_read_ip_net (void (*) (UCHAR *, int));

#ifdef SUPPORT_TCPDUMP
extern void if_close_pcap (int);
extern void if_open_pcap (int);
extern void if_read_ip_pcap (void (*) (UCHAR *, int));
#endif

#if 0
extern void if_read_ip_raw (void (*) (UCHAR *, int));
#endif
