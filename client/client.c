#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <time.h>

enum FLAGS {
    FIN,
    SYN,
    RST,
    PSH,
    ACK,
    URG
};
enum TCP_STATES {
    STATE_SYN,
    STATE_SYN_ACK,
    STATE_ACK
};

#define SYN_S ((0) ^ (1 << SYN))
#define SYN_ACK_S ((SYN_S) ^ (1 << ACK))
#define ACK_S ((0) ^ (1 << ACK))

typedef struct _TCP_Header {
    uint16_t src_port;
    uint16_t des_port;
    uint32_t seq_num;
    uint32_t ack_num;
    unsigned char offset;
    unsigned char flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} TCP_Header;

TCP_Header* create_header(int seq, int src_port, int des_port);
void delete_header(TCP_Header* header);
void print_header(TCP_Header* hdr, int sending, const char* state);
void print_header_helper(TCP_Header* hdr, const char* pred, const char* action, const char* host, const char* state);
int establish_connection(int port, TCP_Header* hdr);
unsigned char* cpy_header(unsigned char* orig);
const char* get_state(char flags, int state);

TCP_Header* create_header(int seq, int src_port, int des_port)
{
    TCP_Header* this = malloc(sizeof(*this));
    memset(this, 0, sizeof(*this));
    this->seq_num  = seq;
    this->src_port = src_port;
    this->des_port = des_port;
    return this;
}

void toggle_flags(unsigned char* flags, int val)
{
    *flags = (*flags) ^ (1 << val);
}

void print_header(TCP_Header* hdr, int sending, const char* state)
{
    if (sending) {
        print_header_helper(hdr, "TO", "SENDING", "SERVER", state);
    } else {
        print_header_helper(hdr, "FROM", "RECEIVED", "SERVER", state);
    }
}

void print_header_helper(TCP_Header* hdr, const char* pred, const char* action, const char* host, const char* state)
{
    int i, width;

    width = 10;

    printf("\n%s %s %s %s", action, state, pred, host);
    printf("\n****************************************");
    printf("\n TCP HEADER:");
    printf("\n  Source Port:               %*u", width, hdr->src_port);
    printf("\n  Destination Port:          %*u", width, hdr->des_port);
    printf("\n  Sequence Number:           %*u", width, hdr->seq_num);
    printf("\n  Acknowledgement Number:    %*u", width, hdr->ack_num);
    printf("\n  Offset:                          ");

    for (i = 8; i > 4; i--) {
        printf("%c", ((hdr->offset) & (1 << i)) ? '1' : '0');
    }

    printf("\n Reserved:                         ");

    for (; i > 0; i--) {
        printf("%c", ((hdr->offset) & (1 << i)) ? '1' : '0');
    }

    printf("\n  Flags:                     ");
    printf("\n     URG is %*c", width, ((hdr->flags) & (1 << 5)) ? '1' : '0');
    printf("\n     ACK is %*c", width, ((hdr->flags) & (1 << 4)) ? '1' : '0');
    printf("\n     PSH is %*c", width, ((hdr->flags) & (1 << 3)) ? '1' : '0');
    printf("\n     RST is %*c", width, ((hdr->flags) & (1 << 2)) ? '1' : '0');
    printf("\n     SYN is %*c", width, ((hdr->flags) & (1 << 1)) ? '1' : '0');
    printf("\n     FIN is %*c", width, ((hdr->flags) & (1 << 0)) ? '1' : '0');
    printf("\n  Window  :                  %*u", width, hdr->window);
    printf("\n  Checksum:                  %*x", width, hdr->checksum);
    printf("\n  Urgent:                    %*u", width, hdr->urgent);
    printf("\n ***************************************\n");
}

int establish_connection(int port, TCP_Header* hdr)
{
    struct sockaddr_in server_address, client_address;
    int sock;
    unsigned int client_port;
    socklen_t addr_size, len;

    printf("_________ .__  .__               __   \n");
    printf("\\_   ___ \\|  | |__| ____   _____/  |_ \n");
    printf("/    \\  \\/|  | |  |/ __ \\ /    \\   __\\\n");
    printf("\\     \\___|  |_|  \\  ___/|   |  \\  |  \n");
    printf(" \\______  /____/__|\\___  >___|  /__|  \n");
    printf("        \\/             \\/     \\/      \n");

    printf("Opening Client socket\n");
    if ((sock = socket(AF_INET, SOCK_STREAM, 0))) {
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port   = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);
    addr_size = sizeof(server_address);

    printf("Connecting to Server\n");
    if ((connect(sock, (struct sockaddr*)&server_address, addr_size))) {
    }
    printf("\nHTTP connection Established\n");

    bzero(&client_address, sizeof(client_address));
    len = sizeof(client_address);
    getsockname(sock, (struct sockaddr*)&client_address, &len);
    client_port = ntohs(client_address.sin_port);

    hdr->src_port = (unsigned)client_port;

    return sock;
}

unsigned char* cpy_header(unsigned char* orig)
{
    int i, len;
    unsigned char* dest;

    len  = sizeof(orig);
    dest = malloc(len);
    for (i = 0; i < len; i++) {
        dest[i] = orig[i];
    }
    return dest;
}

const char* get_state(char flags, int state)
{
    const char* states[3] = { "SYN", "SYN_ACK", "ACK" };
    if (state > 2)
        return "ERROR";
    return states[state];
}

int main(int argc, char** argv)
{
    int port, sock, state;
    TCP_Header* header;
    TCP_Header* cpy;

    if ((argc != 2) || (sscanf(argv[1], "%d", &port) != 1)) {
        fprintf(stderr, "Usage: %s <integer>\n", argv[0]);
        exit(1);
    }

    srand(time(0));
    header        = create_header(256, 0, port);
    sock          = establish_connection(port, header);
    state         = 0;
    header->flags = (header->flags) ^ (1 << SYN);
    cpy           = (TCP_Header*)cpy_header((unsigned char*)header);

    printf("------------------------------------------------------------------\n");
    printf("Initiating Handshake\n\n");
    while (state < 3) {
        switch (state) {
        case STATE_SYN:
            print_header(header, 1, get_state(header->flags, state++));
            header->seq_num = htonl(header->seq_num);
            send(sock, header, sizeof(*header), 0);
            break;

        case STATE_SYN_ACK:
            recv(sock, header, sizeof(*header), 0);
            print_header(header, 0, get_state(header->flags, STATE_SYN_ACK));

            state += (header->flags == SYN_ACK_S);
            /* If the ack number is incorrect, move to previous state */
            state -= (header->ack_num != (cpy->seq_num + 1));

            header->des_port = header->src_port;
            header->src_port = cpy->src_port;
            header->ack_num  = ++header->seq_num;
            header->seq_num  = ++cpy->seq_num;
            header->flags    = (header->flags) ^ (1 << SYN);
            break;

        case STATE_ACK:
            print_header(header, 1, get_state(header->flags, state++));
            send(sock, header, sizeof(*header), 0);
            break;
        default:
            break;
        }
    }
    free(cpy);
    free(header);
    return 0;
}