#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>


typedef struct bleno_header_ {
    uint8_t type;
    uint32_t length;
} __attribute__((__packed__)) bleno_header;

#define L2CAP_CID_ATT           0x0004
#define L2CAP_CID_LE_SIGNALING  0x0005

#define L2CAP_SOCK_OPT_CONN_PARAM 0x04

#define L2CAP_CONN_PARAM_UPDATE_REQ 0x12
#define HCI_CHANNEL_USER	1

#define CMD_SET_ADVERTISEMENT_DATA 0
#define CMD_SET_ADVERTISEMENT_DATA_STR "advertise"
#define CMD_SET_LATENCY 1
#define CMD_SET_LATENCY_STR "latency"
#define CMD_DATA 2
#define CMD_DATA_STR "data"
#define CMD_DISCONNECT 3
#define CMD_DISCONNECT_STR "disconnect"
#define CMD_READ_RSSI 4
#define CMD_READ_RSSI_STR "readrssi"
#define CMD_RSSI 5
#define CMD_RSSI_STR "l2cap_rssi"
#define CMD_DISCONNECTED 6
#define CMD_DISCONNECTED_STR "l2cap_disconnect"
#define CMD_ACCEPTED 7
#define CMD_ACCEPTED_STR "l2cap_accept"
#define CMD_HCIHANDLE 8
#define CMD_HCIHANDLE_STR "l2cap_hciHandle"
#define CMD_ADAPTERSTATE 9
#define CMD_ADAPTERSTATE_STR "adapterState"
#define CMD_SECURITY    10
#define CMD_SECURITY_STR "l2cap_security"
#define CMD_L2CAP_DATA 11
#define CMD_L2CAP_DATA_STR "l2cap_data"

#define BUFSIZ 256000
char stdinbuffer[BUFSIZ];

static const int L2CAP_SO_SNDBUF = 400 * 1024;

int lastSignal = 0;

static void signalHandler(int signal) {
    lastSignal = signal;
}

struct acl_request {
    uint16_t handle;
    uint16_t chanid;
    uint8_t command;
    int      event;
    int      dlen;
    void     *data;
    int     rlen;
    void    *rparam;
};


typedef struct {
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t slave_latency;
	uint16_t timeout_multiplier;
} __attribute__((__packed__)) conn_param_update_req;

typedef struct {
    uint16_t acl_length; //1+1+2+8 = 12
    uint16_t channel_id;
} __attribute__((__packed__)) acl_header;


typedef struct {
    uint8_t code; // 0x12
    uint8_t identifier;
    uint16_t length;
} __attribute__((__packed__)) le_signaling_packet;

typedef struct {
    uint16_t acl_length; //1+1+2+8 = 12
    uint16_t channel_id;
    uint8_t code; // 0x12
    uint8_t identifier;
    uint16_t sig_length; // 2+2+2+2 = 8
    uint16_t min_interval;
    uint16_t max_interval;
    uint16_t slave_latency;
    uint16_t timeout_multiplier;
} __attribute__((__packed__)) le_signaling_packet_conn_update_req;


int le_send_acl(int dd, uint16_t handle, uint8_t dlen, void *data)
{
    uint8_t type = HCI_ACLDATA_PKT;
    hci_acl_hdr ha;
    uint16_t flags = acl_flags(btohs(handle));
    ha.handle = htobs(acl_handle_pack(handle, flags));
    ha.dlen = dlen;
    
    static uint8_t buf[4096];
    buf[0] = type;
    memcpy(buf + 1, &ha, HCI_ACL_HDR_SIZE);
    memcpy(buf + 1 + HCI_ACL_HDR_SIZE, data, dlen);
    
    while (write(dd, buf, dlen + 1 + HCI_ACL_HDR_SIZE) < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            printf("Latency: error\n");
            continue;
        }
        printf("Latency: write failed\n");
        return -1;
    }
    printf("Latency: written\n");
    return 0;
}


int le_send_acl2(int dd, uint16_t handle, uint16_t channel, uint8_t cmd_identifier, uint16_t dlen, void* data)
{
    uint8_t type = HCI_ACLDATA_PKT;
    hci_acl_hdr ha;
    uint16_t flags = 0x03;//acl_flags(btohs(handle));
    uint8_t packet[1024];
    uint16_t total_len, i;
    acl_header* acl = (acl_header*)packet;
    le_signaling_packet* signaling_header = (le_signaling_packet*)(packet+sizeof(acl_header));
    
    acl->acl_length = htobs(sizeof(le_signaling_packet) + dlen);
    acl->channel_id = htobs(channel);
    
    signaling_header->code = cmd_identifier;
    signaling_header->identifier = 0x1;
    signaling_header->length = htobs(dlen);
    
    printf("Pos of data %p\n", data);
    
    memcpy((void*)(packet+sizeof(acl_header)+sizeof(le_signaling_packet)), data, dlen);
    total_len = sizeof(acl_header) + sizeof(le_signaling_packet) + dlen;
    
    
    
    
    for (i= 0; i < total_len; i++) {
        printf("%02x", packet[i]);
    }
    printf("DONE\n");
    
    
    
    ha.handle = htobs(acl_handle_pack(handle, flags));
    ha.dlen = htobs(total_len);
    
    static uint8_t buf[4096];
    buf[0] = type;
    memcpy(buf + 1, &ha, HCI_ACL_HDR_SIZE);
    memcpy(buf + 1 + HCI_ACL_HDR_SIZE, packet, total_len);
    
    while (write(dd, buf, total_len + 1 + HCI_ACL_HDR_SIZE) < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            printf("Latency: error\n");
            continue;
        }
        printf("Latency: write failed\n");
        return -1;
    }
    printf("Latency: written\n");
    return 0;
}

int le_send_alc_request(int dd, struct acl_request* r, int to) {
    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
    struct hci_filter nf, of;
    socklen_t olen;
    
    hci_event_hdr *hdr;
    int err, try;
    
    
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_ACLDATA_PKT,  &nf);
    hci_filter_all_events(&nf);
    //hci_filter_set_opcode(opcode, &nf);
    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
    {
        printf("Error getting filters\n");
        return -1;
    }
    
    if (le_send_acl2(dd, r->handle, r->chanid, r->command, r->dlen, r->data) < 0) {
        printf("Failed sending acl");
        goto failed;
    }
    
	unsigned char control[64];
	struct msghdr msg;
	struct iovec iov;
    
    
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
    
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
    
	while (1) {
		struct cmsghdr *cmsg;
		struct timeval *tv = NULL;
		int *dir = NULL;
		ssize_t len;
        len = 0;
		len = recvmsg(dd, &msg, MSG_DONTWAIT);
		if (len < 0) {
            /*
             if (errno == EAGAIN) {
             printf("No data on socket yet, retrying");
             sleep(1);
             continue;
             }
             */
            printf("hci socket collapsed\n");
			break;
        }
        
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_HCI)
            continue;
            
			switch (cmsg->cmsg_type) {
                case HCI_DATA_DIR:
                    dir = (int *) CMSG_DATA(cmsg);
                    break;
                case HCI_CMSG_TSTAMP:
                    tv = (struct timeval *) CMSG_DATA(cmsg);
                    break;
			}
		}
        
		if (!dir || len < 1){
            printf("NO DATA YET");
            sleep(1);
			continue;
        }
        
        printf("GOT DATA ON HCI SOCKET");
    }
	
    // errno = ETIMEDOUT;
    
failed:
	err = errno;
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	errno = err;
    printf("Errno %s", strerror(errno));
	return -1;
    
done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	return 0;
}

int le_slave_conn_update(int dd, uint16_t handle, uint16_t min, uint16_t max,
                         uint16_t latency, uint16_t to_multiplier)
{
    int eventfd;
    fd_set rfds;
    struct timeval timeout;
    int len, i, result;
    uint8_t buffer[HCI_MAX_EVENT_SIZE];
    le_signaling_packet_conn_update_req sig;
    memset(&sig, 0, sizeof(sig));
    //fill acl header
    sig.acl_length = htobs(12);
    sig.channel_id = htobs(L2CAP_CID_LE_SIGNALING);
    
    // fill header
    sig.code = L2CAP_CONN_PARAM_UPDATE_REQ;
    sig.identifier = (uint8_t)rand();
    sig.sig_length = htobs(8);
    
    // fill payload
    sig.min_interval = htobs(min);
    sig.max_interval = htobs(max);
    sig.slave_latency = htobs(latency);
    sig.timeout_multiplier = htobs(to_multiplier);
    
    
    
    
    le_send_acl(dd, handle, sizeof(sig), &sig);
    
}

int le_slave_conn_update2(int dd, uint16_t handle, uint16_t min, uint16_t max,
                          uint16_t latency, uint16_t to_multiplier)
{
    
    struct acl_request rq;
    conn_param_update_req req;
    int i = 0;
    
    memset(&rq, 0, sizeof(struct acl_request));
    memset(&req, 0, sizeof(conn_param_update_req));
    
    req.min_interval = htobs(min);
    req.max_interval = htobs(max);
    req.slave_latency = htobs(latency);
    req.timeout_multiplier = htobs(to_multiplier);
    
    printf("DATA SET TO ");
    for (; i < sizeof(conn_param_update_req); i++) {
        printf("%02x", *(((uint8_t*)&req)+i));
    }
    printf("END\n");
    printf("Pos of data %p\n", &req);
    rq.handle = handle;
    rq.chanid = L2CAP_CID_LE_SIGNALING;
    rq.command = L2CAP_CONN_PARAM_UPDATE_REQ;
    rq.data = &req;
    rq.dlen = sizeof(conn_param_update_req);
    
    if(le_send_alc_request(dd, &rq, 1000) < 0) {
        printf("Error setting conn update\n");
    }else {
        printf("Conn update success\n");
    }
    
}

int hci_reset(int ctl, int hdev)
{
    
    if (ioctl(ctl, HCIDEVDOWN, hdev) < 0) {
        fprintf(stderr, "Can't down device hci%d: %s (%d)\n", hdev, strerror(errno), errno);
    }
    
    if (ioctl(ctl, HCIDEVUP, hdev) < 0) {
        if (errno == EALREADY)
        return;
        fprintf(stderr, "Can't init device hci%d: %s (%d)\n", hdev, strerror(errno), errno);
    }
    
}

int hci_le_set_advertising_data(int dd, uint8_t* data, uint8_t length, int to)
{
    struct hci_request rq;
    le_set_advertising_data_cp data_cp;
    uint8_t status;
    
    memset(&data_cp, 0, sizeof(data_cp));
    data_cp.length = length;
    memcpy(&data_cp.data, data, sizeof(data_cp.data));
    
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
    rq.cparam = &data_cp;
    rq.clen = LE_SET_ADVERTISING_DATA_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;
    
    if (hci_send_req(dd, &rq, to) < 0)
    return -1;
    
    if (status) {
        errno = EIO;
        return -1;
    }
    
    return 0;
}

int hci_le_set_scan_response_data(int dd, uint8_t* data, uint8_t length, int to)
{
    struct hci_request rq;
    le_set_scan_response_data_cp data_cp;
    uint8_t status;
    
    memset(&data_cp, 0, sizeof(data_cp));
    data_cp.length = length;
    memcpy(&data_cp.data, data, sizeof(data_cp.data));
    
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_SCAN_RESPONSE_DATA;
    rq.cparam = &data_cp;
    rq.clen = LE_SET_SCAN_RESPONSE_DATA_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;
    
    if (hci_send_req(dd, &rq, to) < 0)
    return -1;
    
    if (status) {
        errno = EIO;
        return -1;
    }
    
    return 0;
}

static int create_socket(uint16_t index, uint16_t channel)
{
    struct sockaddr_hci addr;
    int fd;
    
    fd = socket(PF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                BTPROTO_HCI);
    if (fd < 0)
    return -1;
    
    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = index;
    addr.hci_channel = channel;
    
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    
    return fd;
}


int8_t read_rssi(int hciSocket, int hciHandle) {
    int8_t rssi = 0;
    int i;
    for (i = 0; i < 100; i++) {
        hci_read_rssi(hciSocket, hciHandle, &rssi, 1000);
        
        if (rssi != 0) {
            break;
        }
    }
    
    if (rssi == 0) {
        rssi = 127;
    }
    
    return rssi;
}


void process_data(int clientSocket, uint8_t* buf, int len)
{
    int i = 0;
    int j = 0;
    int skip = 0;
    uint8_t l2capSockBuf[512];
    uint32_t data_len;
    int len_written;
    struct timespec tim;
    tim.tv_sec = 0;
    tim.tv_nsec = 100000000L;
    
    //printf("Attempting to write %d bytes to l2capsocket", len);
    
    len_written = write(clientSocket, buf, len);
    
    if (len_written == -1) {
        printf("Error writing to client %d: %s\n", errno, strerror(errno));
    }
}


void set_latency(int hciSocket, uint8_t* buf, int len)
{
    int i = 0;
    uint8_t outbuf[256];
    while(buf[i] != '\n') {
        unsigned int data = 0;
        sscanf((char*)&buf[i], "%02x", &data);
        outbuf[i / 2] = data;
        i += 2;
    }
    uint16_t* bufbufbuf = (uint16_t*)outbuf;
    uint16_t handle = btohs(*bufbufbuf);
    uint16_t min = btohs(*(bufbufbuf+1));
    uint16_t max = btohs(*(bufbufbuf+2));
    uint16_t latency = btohs(*(bufbufbuf+3));
    uint16_t to_multiplier = btohs(*(bufbufbuf+4));
    printf("Setting latency to %d (*1.25ms) %d (*1.25ms) %d %d \n", min, max, latency, to_multiplier);
    
    le_slave_conn_update2(hciSocket, handle, min, max, latency, to_multiplier);
}

void set_latency_opt(int l2capSock, uint8_t* buf, int len)
{
    conn_param_update_req req;
    
    uint16_t* bufbufbuf = (uint16_t*)buf;
    uint16_t handle = ntohs(*bufbufbuf);
    uint16_t min = ntohs(*(bufbufbuf+1));
    uint16_t max = ntohs(*(bufbufbuf+2));
    uint16_t latency = ntohs(*(bufbufbuf+3));
    uint16_t to_multiplier = ntohs(*(bufbufbuf+4));
    printf("Setting latency to %d (*1.25ms) %d (*1.25ms) %d %d \n", min, max, latency, to_multiplier);
    
    req.min_interval = min;
	req.max_interval = max;
	req.slave_latency = latency;
	req.timeout_multiplier = to_multiplier;
    
    if(setsockopt(l2capSock, SOL_L2CAP, L2CAP_SOCK_OPT_CONN_PARAM, &req, sizeof(req)) < 0) {
        printf("FAILED SETTING LATENCY THROUGH SOCK OPTS\n");
    }
}



void set_advertisement_data(int hciSocket, uint8_t* buf, int len) {
    uint8_t advertisementDataBuf[256];
    uint8_t scanDataBuf[256];
    
    uint8_t advertisementDataLen = *buf;
    uint8_t scanDataLen = *(buf+1);
    buf += 2;
    memcpy(advertisementDataBuf, buf, advertisementDataLen);
    memcpy(scanDataBuf, buf+advertisementDataLen, scanDataLen);
    
    
    // stop advertising
    hci_le_set_advertise_enable(hciSocket, 0, 1000);
    
    // set scan data
    hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
    
    // set advertisement data
    hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
    
    // start advertising
    hci_le_set_advertise_enable(hciSocket, 1, 1000);
    
    // set scan data
    hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
    
    // set advertisement data
    hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
}

int strpos(char *haystack, char *needle)
{
    char *p = strstr(haystack, needle);
    if (p)
    return p - haystack;
    return -1;   // Not found = -1.
}



int get_cmd(uint8_t* buf, int* skip_len)
{
    if (strpos((char*)buf, CMD_SET_ADVERTISEMENT_DATA_STR) == 0) {
        *skip_len = strlen(CMD_SET_ADVERTISEMENT_DATA_STR);
        return CMD_SET_ADVERTISEMENT_DATA;
    }else if(strpos((char*)buf, CMD_SET_LATENCY_STR) == 0) {
        *skip_len = strlen(CMD_SET_LATENCY_STR);
        return CMD_SET_LATENCY;
    }else if(strpos((char*)buf, CMD_DATA_STR) == 0) {
        *skip_len = strlen(CMD_DATA_STR);
        return CMD_DATA;
    }else if(strpos((char*)buf, CMD_DISCONNECT_STR) == 0) {
        *skip_len = strlen(CMD_DISCONNECT_STR);
        return CMD_DISCONNECT;
    }else if(strpos((char*)buf, CMD_READ_RSSI_STR) == 0) {
        *skip_len = strlen(CMD_READ_RSSI_STR);
        return CMD_READ_RSSI;
    }
    
    return -1;
}

int main(int argc, const char* argv[])
{
    char *hciDeviceIdOverride = NULL;
    int hciDeviceId = 0;
    int hciSocket;
    struct hci_dev_info hciDevInfo;
    
    int previousAdapterState = -1;
    int currentAdapterState;
    const char* adapterState = NULL;
    
    fd_set rfds;
    struct timeval tv;
    int selectRetval;
    
    uint8_t stdinBuf[256 * 2 + 1 + 10];
    uint8_t hciBuf[1024];
    char advertisementDataBuf[256];
    int advertisementDataLen = 0;
    char scanDataBuf[256];
    int scanDataLen = 0;
    int len;
    int i;
    
    memset(&hciDevInfo, 0x00, sizeof(hciDevInfo));
    
    // buffering aus
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    // setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGKILL, signalHandler);
    signal(SIGHUP, signalHandler);
    signal(SIGUSR1, signalHandler);
    
    prctl(PR_SET_PDEATHSIG, SIGINT);
    
    hciDeviceIdOverride = getenv("BLENO_HCI_DEVICE_ID");
    if (hciDeviceIdOverride != NULL) {
        hciDeviceId = atoi(hciDeviceIdOverride);
    } else {
        // if no env variable given, use the first available device
        hciDeviceId = hci_get_route(NULL);
    }
    
    if (hciDeviceId < 0) {
        hciDeviceId = 0; // use device 0, if device id is invalid
    }
    
    // setup HCI socket
    hciSocket = create_socket(hciDeviceId, HCI_CHANNEL_USER);
    if (hciSocket < 0) {
        printf("HCI_CHANNEL_USER failed");
        hciSocket = hci_open_dev(hciDeviceId);
    }
    hciDevInfo.dev_id = hciDeviceId;
    
    if (hciSocket == -1) {
        printf("adapterState unsupported\n");
        return -1;
    }
    hci_reset(hciSocket, hciDeviceId);
    
    int opt;
    opt = 1;
    if(setsockopt(hciSocket, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0) {
        printf("Error setting data direction\n");
    }
    
    // setup l2cap channel
    int serverL2capSock;
    struct sockaddr_l2 sockAddr;
    socklen_t sockAddrLen;
    int result;
    bdaddr_t clientBdAddr;
    struct l2cap_conninfo l2capConnInfo;
    socklen_t l2capConnInfoLen;
    uint16_t hciHandle;
    bdaddr_t daddr;
    char l2capSockBuf[256];
    struct bt_security btSecurity;
    socklen_t btSecurityLen;
    uint8_t securityLevel = 0;
    
    // create socket
    serverL2capSock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    
    // grab bt addr to bind
    if (hci_read_bd_addr(hciSocket, &daddr, 1000) == -1){
        daddr = *BDADDR_ANY;
    }
    // bind
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.l2_family = AF_BLUETOOTH;
    sockAddr.l2_bdaddr = daddr;
    sockAddr.l2_cid = htobs(L2CAP_CID_ATT);
    
    result = bind(serverL2capSock, (struct sockaddr*)&sockAddr, sizeof(sockAddr));
    
    printf("l2cap_bind %s\n", (result == -1) ? strerror(errno) : "success");
    
    result = listen(serverL2capSock, 2);
    
    printf("l2cap_listen %s\n", (result == -1) ? strerror(errno) : "success");
    
    
    int clientL2capSock = -1;
    
    
    
    int localServerSocket,localClientSocket,n,port;
    localClientSocket = 0;
    struct sockaddr_in servaddr,cliaddr;
    socklen_t addrlen,clilen;
    char mesg[1000];
    
    localServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(0);
    bind(localServerSocket,(struct sockaddr *)&servaddr,sizeof(servaddr));
    addrlen = sizeof(struct sockaddr_in);
    getsockname(localServerSocket,(struct sockaddr*)&servaddr, &addrlen);
    port=ntohs(servaddr.sin_port);
    
    listen(localServerSocket, 1);
    
    printf("localPort %d\n", port);
    
    while(1) {
        uint8_t outbuf[4096];
        bleno_header* out_header = (bleno_header*)outbuf;
        uint8_t* out_data_buf = outbuf + sizeof(bleno_header);
        
        FD_ZERO(&rfds);
        //FD_SET(0, &rfds);
        
        FD_SET(localServerSocket, &rfds);
        if (clientL2capSock > 0) {
            FD_SET(clientL2capSock, &rfds);
        }
        // wait for client before we interact with the socket
        if(localClientSocket > 0) {
            FD_SET(localClientSocket, &rfds);
            FD_SET(hciSocket, &rfds);
            FD_SET(serverL2capSock, &rfds);
        }
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        if (localClientSocket > 0) {
            // get HCI dev info for adapter state
            ioctl(hciSocket, HCIGETDEVINFO, (void *)&hciDevInfo);
            currentAdapterState = hci_test_bit(HCI_UP, &hciDevInfo.flags);
            
            if (previousAdapterState != currentAdapterState) {
                previousAdapterState = currentAdapterState;
                
                if (!currentAdapterState) {
                    adapterState = "poweredOff";
                } else {
                    hci_le_set_advertise_enable(hciSocket, 0, 1000);
                    
                    hci_le_set_advertise_enable(hciSocket, 1, 1000);
                    
                    if (hci_le_set_advertise_enable(hciSocket, 0, 1000) == -1) {
                        if (EPERM == errno) {
                            adapterState = "unauthorized";
                        } else if (EIO == errno) {
                            adapterState = "unsupported";
                        } else {
                            printf("%d\n", errno);
                            adapterState = "unknown";
                        }
                    } else {
                        adapterState = "poweredOn";
                    }
                }
                out_header->type = CMD_ADAPTERSTATE;
                out_header->length = htonl(strlen(adapterState));
                memcpy(out_data_buf, adapterState, ntohl(out_header->length));
                write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                //printf("adapterState %s\n", adapterState);
            }
        }
        
        selectRetval = select(1024, &rfds, NULL, NULL, &tv);
        
        if (selectRetval == -1) {
            if (SIGINT == lastSignal || SIGKILL == lastSignal) {
                // done
                printf("Got sig int or kill\n");
                break;
            } else if (SIGHUP == lastSignal) {
                // stop advertising
                hci_le_set_advertise_enable(hciSocket, 0, 1000);
                
            } else if (SIGUSR1 == lastSignal) {
                // stop advertising
                hci_le_set_advertise_enable(hciSocket, 0, 1000);
                
                // set scan data
                hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
                
                // set advertisement data
                hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
                
                // start advertising
                hci_le_set_advertise_enable(hciSocket, 1, 1000);
                
                // set scan data
                hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
                
                // set advertisement data
                hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
            }
        } else if (selectRetval) {
            if(FD_ISSET(serverL2capSock, &rfds)) {
                // there is a client trying to connect
                sockAddrLen = sizeof(sockAddr);
                clientL2capSock = accept(serverL2capSock, (struct sockaddr *)&sockAddr, &sockAddrLen);
                
                baswap(&clientBdAddr, &sockAddr.l2_bdaddr);
                char* bdaddrstr = batostr(&clientBdAddr);
                out_header->type = CMD_ACCEPTED;
                out_header->length = htonl(strlen(bdaddrstr));
                memcpy(out_data_buf, bdaddrstr, ntohl(out_header->length));
                
                write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                
                //printf("l2cap_accept %s\n", batostr(&clientBdAddr));
                
                l2capConnInfoLen = sizeof(l2capConnInfo);
                getsockopt(clientL2capSock, SOL_L2CAP, L2CAP_CONNINFO, &l2capConnInfo, &l2capConnInfoLen);
                hciHandle = l2capConnInfo.hci_handle;
                
                out_header->type = CMD_HCIHANDLE;
                out_header->length = htonl(sizeof(uint16_t));
                *out_data_buf = htonl((uint16_t)hciHandle);
                write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                
                //printf("l2cap_hciHandle %d\n", hciHandle);
                
            }
            
            if (FD_ISSET(localServerSocket, &rfds)) {
                // accept client
                clilen=sizeof(cliaddr);
                localClientSocket = accept(localServerSocket,(struct sockaddr *)&cliaddr, &clilen);
            }
            
            if (FD_ISSET(localClientSocket, &rfds)) {
                uint8_t inputBuffer[4096];
                bleno_header* header = (bleno_header*)inputBuffer;
                
                int len;
                int offset = 0;
                // read the header
                while (offset != sizeof(bleno_header) && (len = read(localClientSocket, inputBuffer+offset, sizeof(bleno_header)-offset)) > 0) {
                    offset += len;
                }
                if (len <= 0) {
                    close(localClientSocket);
                    break;
                }
                int total_size = sizeof(bleno_header)+ntohl(header->length);
                while (offset != total_size && ((len = read(localClientSocket, inputBuffer+offset, total_size-offset))) > 0) {
                    offset += len;
                }
                if (len <= 0) {
                    close(localClientSocket);
                    break;
                }
                
                uint8_t* data_buf = inputBuffer+sizeof(bleno_header);
                int data_len = ntohl(header->length);
                char* strClientBdAddr;
                
                uint8_t rssi;
                switch (header->type) {
                    case CMD_SET_ADVERTISEMENT_DATA:
                        printf("Got advertisement data\n");
                        set_advertisement_data(hciSocket, data_buf, data_len);
                        break;
                    case CMD_SET_LATENCY:
                        printf("Got latency data\n");
                        set_latency_opt(clientL2capSock, data_buf, data_len);
                        //set_latency(hciSocket, dataBuf, data_len);
                        break;
                    case CMD_DATA:
                        printf("Got data\n");
                        process_data(clientL2capSock, data_buf, data_len);
                        break;
                    case CMD_DISCONNECT:
                        printf("Got disconnect data\n");
                        strClientBdAddr = batostr(&clientBdAddr);
                        out_header->type = CMD_DISCONNECTED;
                        out_header->length = htonl(strlen(strClientBdAddr));
                        memcpy(out_data_buf, strClientBdAddr, ntohl(out_header->length));
                        write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                        
                        //printf("l2cap_disconnect %s\n", batostr(&clientBdAddr));
                        close(clientL2capSock);
                        clientL2capSock = -1;
                        break;
                    case CMD_READ_RSSI:
                        printf("Got read rssi data\n");
                        rssi = read_rssi(hciSocket, hciHandle);
                        out_header->type = CMD_RSSI;
                        out_header->length = htonl(sizeof(uint8_t));
                        *out_data_buf = rssi;
                        
                        write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                        
                        //printf("l2cap_rssi = %d\n", rssi);
                        break;
                    default:
                        break;
                }
                
            }
            
            if (clientL2capSock > 0 && FD_ISSET(clientL2capSock, &rfds)) {
                len = read(clientL2capSock, l2capSockBuf, sizeof(l2capSockBuf));
                
                if (len <= 0) {
                    printf("L2CAP Client sock collapsed\n");
                    close(clientL2capSock);
                    clientL2capSock = 0;
                }else {
                    btSecurityLen = sizeof(btSecurity);
                    memset(&btSecurity, 0, btSecurityLen);
                    getsockopt(clientL2capSock, SOL_BLUETOOTH, BT_SECURITY, &btSecurity, &btSecurityLen);
                    
                    if (securityLevel != btSecurity.level) {
                        securityLevel = btSecurity.level;
                        
                        const char *securityLevelString;
                        
                        switch(securityLevel) {
                            case BT_SECURITY_LOW:
                                securityLevelString = "low";
                                break;
                                
                            case BT_SECURITY_MEDIUM:
                                securityLevelString = "medium";
                                break;
                                
                            case BT_SECURITY_HIGH:
                                securityLevelString = "high";
                                break;
                                
                            default:
                                securityLevelString = "unknown";
                                break;
                        }
                        out_header->type = CMD_SECURITY;
                        out_header->length = htonl(strlen(securityLevelString));
                        memcpy(out_data_buf, securityLevelString, ntohl(out_header->length));
                        write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                        
                        //printf("l2cap_security %s\n", securityLevelString);
                    }
                    
                    out_header->type = CMD_L2CAP_DATA;
                    out_header->length = htonl(len);
                	write(localClientSocket,outbuf, sizeof(bleno_header));
                	write(localClientSocket,l2capSockBuf, len);
                }
                /*
                 printf("l2cap_data ");
                 for(i = 0; i < len; i++) {
                 printf("%02x", ((int)l2capSockBuf[i]) & 0xff);
                 }
                 printf("\n");
                 */
            }
            
            if(FD_ISSET(hciSocket, &rfds)) {
                len = read(hciSocket, (void*)hciBuf, sizeof(hciBuf));
                if (len <= 0) {
                    printf("HCI socket collapsed\n");
                    continue;
                }
                i = 0;
                printf("HCI READ");
                for (i = 0; i < len; i++) {
                    printf("%02x ", hciBuf[i]);
                }
                printf("END\n");
            }
        }
    }
    
    printf("close\n");
    close(localClientSocket);
    close(localServerSocket);
    close(clientL2capSock);
    close(serverL2capSock);
    // stop advertising
    hci_le_set_advertise_enable(hciSocket, 0, 1000);
    
    close(hciSocket);
    
    return 0;
}
