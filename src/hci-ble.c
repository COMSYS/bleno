#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/param.h> /* MAX */
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

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
#define CMD_RESERVED 8
#define CMD_RESERVED_STR "l2cap_hciHandle"
#define CMD_ADAPTERSTATE 9
#define CMD_ADAPTERSTATE_STR "adapterState"
#define CMD_SECURITY    10
#define CMD_SECURITY_STR "l2cap_security"
#define CMD_L2CAP_DATA 11
#define CMD_L2CAP_DATA_STR "l2cap_data"


typedef struct bleno_header_ {
    uint8_t type;
    uint32_t length;
} __attribute__((__packed__)) bleno_header;


char advertisementDataBuf[256];
int advertisementDataLen = 0;
char scanDataBuf[256];
int scanDataLen = 0;

int lastSignal = 0;

static void signalHandler(int signal) {
    lastSignal = signal;
}


typedef struct {
	uint16_t min_interval;
	uint16_t max_interval;
	uint16_t slave_latency;
	uint16_t timeout_multiplier;
} __attribute__((__packed__)) conn_param_update_req;


void hci_reset(int ctl, int hdev)
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


int hci_le_set_advertising_settings(int dd, uint8_t* data, int to)
{
    struct hci_request rq;
    uint8_t status;

    
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
    rq.cparam = data;
    rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
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

int le_set_advertising_enable(int dd, uint8_t enable, int to)
{
    struct hci_request rq;
    le_set_advertise_enable_cp enable_cp;
    uint8_t status;
    
    memset(&enable_cp, 0, sizeof(enable_cp));
    enable_cp.enable = enable;
    
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
    rq.cparam = &enable_cp;
    rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
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

void set_latency_opt(int l2capSock, uint16_t min, uint16_t max, uint16_t latency, uint16_t to_multiplier)
{
    conn_param_update_req req;
    
    printf("Setting latency to %d (*1.25ms) %d (*1.25ms) %d %d \n", min, max, latency, to_multiplier);
    
    req.min_interval = min;
    req.max_interval = max;
    req.slave_latency = latency;
    req.timeout_multiplier = to_multiplier;
    
    if(setsockopt(l2capSock, SOL_L2CAP, L2CAP_SOCK_OPT_CONN_PARAM, &req, sizeof(req)) < 0) {
        printf("FAILED SETTING LATENCY THROUGH SOCK OPTS\n");
    }
}



void set_advertisement_data(int hciSocket, uint8_t* buf, int len)
{
    le_set_advertising_parameters_cp adv_params;
    
    
    if (len < 2) {
        return;
    }
    advertisementDataLen = *buf;
    scanDataLen = *(buf+1);
    buf += 2;
    memcpy(advertisementDataBuf, buf, advertisementDataLen);
    memcpy(scanDataBuf, buf+advertisementDataLen, scanDataLen);
    
    
    /* stop advertising */
    le_set_advertising_enable(hciSocket, 0, 1000);
    
    memset(&adv_params, 0, sizeof(le_set_advertising_parameters_cp));
    adv_params.min_interval = 0x20;
    adv_params.max_interval = 0x20;
    adv_params.chan_map = 0x07;
    
    hci_le_set_advertising_settings(hciSocket, (uint8_t*)&adv_params, 1000);
    /* set scan data */
    hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
    
    /* set advertisement data */
    hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
    
    /* start advertising */
    le_set_advertising_enable(hciSocket, 1, 1000);
    
    /* set scan data */
    hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
    
    /* set advertisement data */
    hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
}


int process_data(int clientSocket, uint8_t* buf, int len)
{
    int len_written;
   
    while(len_written != len && (len_written = write(clientSocket, buf+len_written, len-len_written)) > 0)
    
    if (len_written == -1) {
        printf("Error writing to client %d: %s\n", errno, strerror(errno));
        return -1;
    }
    return 0;
}


int strpos(char *haystack, char *needle)
{
    char *p = strstr(haystack, needle);
    if (p)
    return p - haystack;
    return -1;   /* Not found = -1. */
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

int main()
{
    /* hci stuff */
    char* hciDeviceIdOverride;
    int hciDeviceId, previousAdapterState, currentAdapterState;
    struct hci_dev_info hciDevInfo;
    uint16_t hciHandle;
    bdaddr_t daddr;
    uint8_t hciBuf[1024];
    
    /* sockets */
    int hciSocket, serverL2capSock, clientL2capSock, localServerSocket, localClientSocket;
    int port;
    struct sockaddr_l2 sockAddr;
    socklen_t sockAddrLen, addrlen, clilen;
    bdaddr_t clientBdAddr;
    struct sockaddr_in servaddr, cliaddr;
    
    /* other stuff */
    struct l2cap_conninfo l2capConnInfo;
    socklen_t l2capConnInfoLen;
    struct bt_security btSecurity;
    socklen_t btSecurityLen;
    uint8_t securityLevel;
    
    
    
    
    /* initialize variables */
    previousAdapterState = -1;
    hciDeviceIdOverride = NULL;
    clientL2capSock = -1;
    localClientSocket = -1;
    securityLevel = 0;
    
    /* buffering aus */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    /* setup signal handlers */
    signal(SIGINT, signalHandler);
    signal(SIGKILL, signalHandler);
    signal(SIGHUP, signalHandler);
    signal(SIGUSR1, signalHandler);
    
    prctl(PR_SET_PDEATHSIG, SIGINT);
    
    hciDeviceIdOverride = getenv("BLENO_HCI_DEVICE_ID");
    if (hciDeviceIdOverride != NULL) {
        hciDeviceId = atoi(hciDeviceIdOverride);
    } else {
        /* if no env variable given, use the first available device */
        hciDeviceId = hci_get_route(NULL);
    }
    
    if (hciDeviceId < 0) {
        hciDeviceId = 0; /* use device 0, if device id is invalid */
    }
    
    /* setup HCI socket */
    memset(&hciDevInfo, 0x00, sizeof(hciDevInfo));
    hciSocket = hci_open_dev(hciDeviceId);
    hciDevInfo.dev_id = hciDeviceId;
    if (hciSocket == -1) {
        printf("adapterState unsupported\n");
        return -1;
    }
    
    /* reset hci device */
    hci_reset(hciSocket, hciDeviceId);
    
    /* create socket */
    serverL2capSock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    
    /* grab bt addr to bind */
    if (hci_read_bd_addr(hciSocket, &daddr, 1000) == -1){
        daddr = *BDADDR_ANY;
    }
    /* bind */
    memset(&sockAddr, 0, sizeof(sockAddr));
    sockAddr.l2_family = AF_BLUETOOTH;
    sockAddr.l2_bdaddr = daddr;
    sockAddr.l2_cid = htobs(L2CAP_CID_ATT);
    
    if(bind(serverL2capSock, (struct sockaddr*)&sockAddr, sizeof(sockAddr)) < 0) {
        printf("l2cap_bind %s\n", strerror(errno));
    }else {
        printf("l2cap_bind success\n");
    }
    
    if(listen(serverL2capSock, 2) < 0) {
        printf("l2cap_listen %s\n", strerror(errno));
    }else {
        printf("l2cap_listen success\n");
    }

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
        uint8_t* out_data_buf;
        bleno_header* out_header;
        struct timeval tv;
        int selectRetval, max_sock;
        fd_set rfds;
        
        out_header = (bleno_header*)outbuf;
        out_data_buf= outbuf + sizeof(bleno_header);

        FD_ZERO(&rfds);
        
        FD_SET(localServerSocket, &rfds);
        if (clientL2capSock > 0) {
            FD_SET(clientL2capSock, &rfds);
        }
        /* wait for client before we interact with the socket */
        if(localClientSocket > 0) {
            FD_SET(hciSocket, &rfds);
            FD_SET(serverL2capSock, &rfds);
            FD_SET(localClientSocket, &rfds);
        }
        max_sock = MAX(localServerSocket, MAX(clientL2capSock, MAX(hciSocket, MAX(serverL2capSock, localClientSocket))));
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        if (localClientSocket > 0) {
            const char* adapterState;
            /* get HCI dev info for adapter state */
            ioctl(hciSocket, HCIGETDEVINFO, (void *)&hciDevInfo);
            currentAdapterState = hci_test_bit(HCI_UP, &hciDevInfo.flags);
            
            if (previousAdapterState != currentAdapterState) {
                previousAdapterState = currentAdapterState;
                
                if (!currentAdapterState) {
                    adapterState = "poweredOff";
                } else {
                    le_set_advertising_enable(hciSocket, 0, 1000);
                    
                    le_set_advertising_enable(hciSocket, 1, 1000);
                    
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
            }
        }
        
        selectRetval = select(max_sock+1, &rfds, NULL, NULL, &tv);
        
        if (selectRetval == -1) {
            if (SIGINT == lastSignal || SIGKILL == lastSignal) {
                /* done */
                printf("Got sig int or kill\n");
                break;
            } else if (SIGHUP == lastSignal) {
                /* stop advertising */
                
                printf("SIGHUP stop advertising");
                le_set_advertising_enable(hciSocket, 0, 1000);
                
                
            } else if (SIGUSR1 == lastSignal) {
                le_set_advertising_parameters_cp adv_params;
                
                printf("Reanabling advertisements\n");
               
                usleep(500000);

                le_set_advertising_enable(hciSocket, 0, 1000);
                
                memset(&adv_params, 0, sizeof(le_set_advertising_parameters_cp));
                adv_params.min_interval = 0x20;
                adv_params.max_interval = 0x20;
                adv_params.chan_map = 0x07;
                
                hci_le_set_advertising_settings(hciSocket, (uint8_t*)&adv_params, 1000);
                
                /* set scan data */
                hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
                
                /* set advertisement data */
                hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
                
                /* start advertising */
                le_set_advertising_enable(hciSocket, 1, 1000);
                
                /* set scan data */
                hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);
                
                /* set advertisement data */
                hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
                
            }
        } else if (selectRetval) {
            if(FD_ISSET(serverL2capSock, &rfds)) {
                /* there is a client trying to connect */
                char* bdaddrstr;
                
                sockAddrLen = sizeof(sockAddr);
                clientL2capSock = accept(serverL2capSock, (struct sockaddr *)&sockAddr, &sockAddrLen);
                
                baswap(&clientBdAddr, &sockAddr.l2_bdaddr);
                bdaddrstr = batostr(&clientBdAddr);
                
                l2capConnInfoLen = sizeof(l2capConnInfo);
                getsockopt(clientL2capSock, SOL_L2CAP, L2CAP_CONNINFO, &l2capConnInfo, &l2capConnInfoLen);
                hciHandle = l2capConnInfo.hci_handle;
                
                
                out_header->type = CMD_ACCEPTED;
                out_header->length = htonl(strlen(bdaddrstr)+sizeof(uint16_t));
                *(uint16_t*)out_data_buf = htons((uint16_t)hciHandle);
                memcpy(out_data_buf+sizeof(uint16_t), bdaddrstr, strlen(bdaddrstr));
                
                write(localClientSocket, outbuf, sizeof(bleno_header)+ntohl(out_header->length));
               
            }
            
            if (FD_ISSET(localServerSocket, &rfds)) {
                /* accept client */
                clilen=sizeof(cliaddr);
                localClientSocket = accept(localServerSocket,(struct sockaddr *)&cliaddr, &clilen);
            }
            
            if (FD_ISSET(localClientSocket, &rfds)) {
                uint8_t inputBuffer[4096];
                uint8_t* data_buf;
                bleno_header* header;
                int len, offset, total_size, data_len;
                
                header = (bleno_header*)inputBuffer;
                offset = 0;
                
                /* read the header */
                while (offset != sizeof(bleno_header) && (len = read(localClientSocket, inputBuffer+offset, sizeof(bleno_header)-offset)) > 0) {
                    offset += len;
                }
                if (len <= 0) {
                    close(localClientSocket);
                    break;
                }
                
                total_size = sizeof(bleno_header)+ntohl(header->length);
                
                while (offset != total_size && ((len = read(localClientSocket, inputBuffer+offset, total_size-offset))) > 0) {
                    offset += len;
                }
                if (len <= 0) {
                    close(localClientSocket);
                    break;
                }
                
                data_buf = inputBuffer+sizeof(bleno_header);
                data_len = ntohl(header->length);
                
                
                switch (header->type) {
                    case CMD_SET_ADVERTISEMENT_DATA:
                        printf("Got advertisement data\n");
                        set_advertisement_data(hciSocket, data_buf, data_len);
                        break;
                        
                    case CMD_SET_LATENCY:
                        printf("Got latency data\n");
                        set_latency_opt(clientL2capSock, ntohs(*(data_buf+2)), ntohs(*(data_buf+4)), ntohs(*(data_buf+6)), ntohs(*(data_buf+8)));
                        break;
                        
                    case CMD_DATA:
                        printf("Got data\n");
                        if (process_data(clientL2capSock, data_buf, data_len) == -1) {
                            char* strClientBdAddr;
                            
                            strClientBdAddr = batostr(&clientBdAddr);
                            out_header->type = CMD_DISCONNECTED;
                            out_header->length = htonl(strlen(strClientBdAddr));
                            memcpy(out_data_buf, strClientBdAddr, ntohl(out_header->length));
                            write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                            
                            close(clientL2capSock);
                            clientL2capSock = -1;
                        }
                        break;
                        
                    case CMD_DISCONNECT:
                        printf("Got disconnect data\n");
                        hci_disconnect(hciSocket, hciHandle, HCI_OE_USER_ENDED_CONNECTION, 1000);
                        break;
                        
                    case CMD_READ_RSSI:
                    {
                        uint8_t rssi;
                        printf("Got read rssi data\n");
                        rssi = read_rssi(hciSocket, hciHandle);
                        out_header->type = CMD_RSSI;
                        out_header->length = htonl(sizeof(uint8_t));
                        *out_data_buf = rssi;
                        
                        write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                        
                        break;
                    }
                        
                    default:
                        break;
                }
                
            }
            
            if (clientL2capSock > 0 && FD_ISSET(clientL2capSock, &rfds)) {
                int len;
                char l2capSockBuf[1024];
                len = read(clientL2capSock, l2capSockBuf, sizeof(l2capSockBuf));
                
                if (len <= 0) {
                    char* strClientBdAddr;
                    
                    printf("L2CAP Client sock collapsed\n");
                    
                    strClientBdAddr = batostr(&clientBdAddr);
                    out_header->type = CMD_DISCONNECTED;
                    out_header->length = htonl(strlen(strClientBdAddr));
                    memcpy(out_data_buf, strClientBdAddr, ntohl(out_header->length));
                    write(localClientSocket,outbuf, sizeof(bleno_header)+ntohl(out_header->length));
                    
                    close(clientL2capSock);
                    clientL2capSock = -1;
                }else {
                    btSecurityLen = sizeof(btSecurity);
                    memset(&btSecurity, 0, btSecurityLen);
                    getsockopt(clientL2capSock, SOL_BLUETOOTH, BT_SECURITY, &btSecurity, &btSecurityLen);
                    
                    if (securityLevel != btSecurity.level) {
                        const char *securityLevelString;
                        
                        securityLevel = btSecurity.level;
                        
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
                int len, i;
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
    /* stop advertising */
    hci_le_set_advertise_enable(hciSocket, 0, 1000);
    
    close(hciSocket);
    
    return 0;
}
