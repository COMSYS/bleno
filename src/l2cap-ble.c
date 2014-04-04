#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#define ATT_CID 4
#define L2CAP_CONN_PARAM_UPDATE_REQ 0x12

int lastSignal = 0;

static void signalHandler(int signal) {
  lastSignal = signal;
}



struct l2cap_conn_param_update_req {
	uint16_t      min;
	uint16_t      max;
	uint16_t      latency;
	uint16_t      to_multiplier;
} __attribute__((__packed__));

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

void le_slave_conn_update(int dd, uint16_t handle, uint16_t min, uint16_t max,
                          uint16_t latency, uint16_t to_multiplier)
{
    le_signaling_packet_conn_update_req sig;
    memset(&sig, 0, sizeof(sig));
    //fill acl header
    sig.acl_length = htobs(12);
    sig.channel_id = htobs(0x0005);
    
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
int strpos(char *haystack, char *needle)
{
    char *p = strstr(haystack, needle);
    if (p)
        return p - haystack;
    return -1;   // Not found = -1.
}

int main(int argc, const char* argv[]) {

  char *hciDeviceIdOverride = NULL;
  int hciDeviceId = 0;
  int hciSocket;
  
  int serverL2capSock;
  struct sockaddr_l2 sockAddr;
  socklen_t sockAddrLen;
  int result;
  bdaddr_t clientBdAddr;
  int clientL2capSock;
  struct l2cap_conninfo l2capConnInfo;
  socklen_t l2capConnInfoLen;
  int hciHandle;

  fd_set afds;
  fd_set rfds;
  struct timeval tv;

  char stdinBuf[256 * 2 + 1 + 10];
  char l2capSockBuf[256];
  int len;
  int i;
  struct bt_security btSecurity;
  socklen_t btSecurityLen;
  uint8_t securityLevel = 0;
  
  srand(time(NULL));

  // remove buffering 
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // setup signal handlers
  signal(SIGINT, signalHandler);
  signal(SIGKILL, signalHandler);
  signal(SIGHUP, signalHandler);
  signal(SIGUSR1, signalHandler);

  prctl(PR_SET_PDEATHSIG, SIGINT);

  // create socket
  serverL2capSock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
  
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
  
  bdaddr_t daddr;
  hciSocket = hci_open_dev(hciDeviceId);
  if (hciSocket == -1) {
    printf("adapterState unsupported\n");
    return -1;
  }
  if (hci_read_bd_addr(hciSocket, &daddr, 1000) == -1){
    daddr = *BDADDR_ANY;
  }

  // bind
  memset(&sockAddr, 0, sizeof(sockAddr));
  sockAddr.l2_family = AF_BLUETOOTH;
  sockAddr.l2_bdaddr = daddr;
  sockAddr.l2_cid = htobs(ATT_CID);

  result = bind(serverL2capSock, (struct sockaddr*)&sockAddr, sizeof(sockAddr));

  printf("bind %s\n", (result == -1) ? strerror(errno) : "success");

  result = listen(serverL2capSock, 1);

  printf("listen %s\n", (result == -1) ? strerror(errno) : "success");

  while (result != -1) {
    FD_ZERO(&afds);
    FD_SET(serverL2capSock, &afds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    result = select(serverL2capSock + 1, &afds, NULL, NULL, &tv);

    if (-1 == result) {
      if (SIGINT == lastSignal || SIGKILL == lastSignal) {
        break;
      } else if (SIGHUP == lastSignal || SIGUSR1 == lastSignal) {
        result = 0;
      }
    } else if (result && FD_ISSET(serverL2capSock, &afds)) {
      sockAddrLen = sizeof(sockAddr);
      clientL2capSock = accept(serverL2capSock, (struct sockaddr *)&sockAddr, &sockAddrLen);

      baswap(&clientBdAddr, &sockAddr.l2_bdaddr);
      printf("accept %s\n", batostr(&clientBdAddr));

      l2capConnInfoLen = sizeof(l2capConnInfo);
      getsockopt(clientL2capSock, SOL_L2CAP, L2CAP_CONNINFO, &l2capConnInfo, &l2capConnInfoLen);
      hciHandle = l2capConnInfo.hci_handle;
        
      printf("hciHandle %d\n", hciHandle);
      while(1) {
        FD_ZERO(&rfds);
        FD_SET(0, &rfds);
        FD_SET(clientL2capSock, &rfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        result = select(clientL2capSock + 1, &rfds, NULL, NULL, &tv);

        if (-1 == result) {
          if (SIGINT == lastSignal || SIGKILL == lastSignal) {
            break;
          } else if (SIGHUP == lastSignal) {
            result = 0;

            hci_disconnect(hciSocket, hciHandle, HCI_OE_USER_ENDED_CONNECTION, 1000);
          } else if (SIGUSR1 == lastSignal) {
            int8_t rssi = 0;

            for (i = 0; i < 100; i++) {
              hci_read_rssi(hciSocket, hciHandle, &rssi, 1000);

              if (rssi != 0) {
                break;
              }
            }
            
            if (rssi == 0) {
              rssi = 127;
            }

            printf("rssi = %d\n", rssi);
          }
        } else if (result) {
          if (FD_ISSET(0, &rfds)) {
            len = read(0, stdinBuf, sizeof(stdinBuf));

            if (len <= 0) {
              break;
            }
            if (strpos(stdinBuf, "latency") == 0) {
              char* buffer = stdinBuf+7;
              i = 0;
              char outbuf[256];
              while(buffer[i] != '\n') {
                  unsigned int data = 0;
                  sscanf(&buffer[i], "%02x", &data);
                  outbuf[i / 2] = data;
                  i += 2;
              }
              uint16_t* bufbufbuf = (uint16_t*)outbuf;
              uint16_t handle = btohs(*bufbufbuf)
              uint16_t min = btohs(*(bufbufbuf+1));
              uint16_t max = btohs(*(bufbufbuf+2));
              uint16_t latency = btohs(*(bufbufbuf+3));
              uint16_t to_multiplier = btohs(*(bufbufbuf+4));
              printf("Setting latency to %d (*1.25ms) %d (*1.25ms) %d %d \n", min, max, latency, to_multiplier);
              le_slave_conn_update(hciSocket, handle, min, max, latency, to_multiplier);
              // todo block for read on hci socket
              //read(hciSocket, l2capSockBuf, sizeof(l2capSockBuf));
              
              
            }else if (strpos(stdinBuf, "data") == 0)  {
              char* buffer = stdinBuf+4;
              i = 0;
              while(buffer[i] != '\n') {
                  unsigned int data = 0;
                  sscanf(&buffer[i], "%02x", &data);
                  l2capSockBuf[i / 2] = data;
                  i += 2;
              }
              // -1 for \n  -4 for "data"
              len = write(clientL2capSock, l2capSockBuf, (len - 1 - 4) / 2);
            }

          }

          if (FD_ISSET(clientL2capSock, &rfds)) {
            len = read(clientL2capSock, l2capSockBuf, sizeof(l2capSockBuf));

            if (len <= 0) {
              break;
            }
              
            

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

              printf("security %s\n", securityLevelString);
            }

            printf("data ");
            for(i = 0; i < len; i++) {
              printf("%02x", ((int)l2capSockBuf[i]) & 0xff);
            }
            printf("\n");
          }
        }
      }

      printf("disconnect %s\n", batostr(&clientBdAddr));
      close(clientL2capSock);
    }
  }

  printf("close\n");
  close(serverL2capSock);
  close(hciSocket);

  return 0;
}
