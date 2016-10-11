//#include <QCoreApplication>
#include <stdio.h>
#include <memory.h>
//#include <math.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#define MAX_PCAP_FILE_SIZE 65536  //65536 BYTE


FILE *fp=NULL;

// TCP Header
typedef u_int tcp_seq;

struct TCP_hdr{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS    (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

//IP Header


int ProcessFrame(unsigned char *Frame_Data,int Frame_Length)
{
    struct ip *ip;
    struct TCP_hdr *tcp;
    unsigned int IP_header_length;
    printf("\nProcessing Frame\n");

    if(Frame_Length < sizeof(struct ether_header)){
        printf("\n Packet size is lessthan Ethernet Header");
        return 0;
    }
    // Skipping Ethernet Header
    Frame_Data +=sizeof(struct ether_header);
    Frame_Length -=sizeof(struct ether_header);

    if(Frame_Length < sizeof(struct ip)){
        printf("\n Packet size is less than IP Header");
        return 0;
    }
    ip= (struct ip*) Frame_Data;  // IP pointer
    IP_header_length = ip->ip_hl * 4;

    if(Frame_Length < IP_header_length){
        printf("\n IP Header is not captured with options");
        return 0;
    }
    if(ip->ip_p != IPPROTO_TCP){
        printf("\n This is non TCP Packet\n");
        return 1;
    }
    // Skipping IP Header to TCP Header
    Frame_Data +=IP_header_length;
    Frame_Length -= IP_header_length;

    if(Frame_Length < sizeof(struct TCP_hdr)){
        printf("\n Packet size is less than TCP Header\n");
        return 0;
    }
    tcp=(struct TCP_hdr*) Frame_Data;
    printf("TCP src_port=%d dst_port=%d \n",
           ntohs(tcp->th_sport),
           ntohs(tcp->th_dport));
    return 1;
}

int main(int argc, char *argv[])
{
    int i,j;
    int arg_max_length=15;
    int FlagFileOpen=0;

    int FrameLength;
    unsigned char FrameData[MAX_PCAP_FILE_SIZE];

    memset(FrameData,0xFF,sizeof(FrameData));

/*************************** To Parse Command Line Arguments******************************/

    //To skip the Programm Name
    ++argv;--argc;

    // No.of command line arguments checking and restricting to only one argument.
    if(argc < 1)
    {
        printf("\n Programm Requires one Argument, the PCAP file!!\n");
        return 0;
    }
    else if(argc>1){
        printf("\n Too many Arguments, Programme Accepts only one Argument. Bye!!\n");
        return 0;
    }
    else{
        int arglen=strlen(argv[0]);

        //File name length checking.
        if(arglen >arg_max_length){
            printf("\n File name is too big, Don't try to crash our programme!!!\n");
            return 0;
        }

        //Special character checking in file name.
        int special_flag=0;
        for(int i=0;i<arglen;i++){
            //printf("\n%c",argv[0][i]);
            switch(argv[0][i])
            {
                case '\\':  printf("\n Back slash is detected, It is not allowed in File-name.\n");
                            special_flag=1;
                            break;
                case '*':   printf("\n Star symbol is detected, It is not allowed in File-name.\n");
                            special_flag=1;
                            break;
                case '\'':  printf("\n single quote is detected, It is not allowed in File-name.\n");
                            special_flag=1;
                            break;
                case '"':   printf("\n Double quote is detected, It is not allowed in File-name.\n");
                            special_flag=1;
                            break;
                // we can add speical characters here, if any.
            }
            if(special_flag==1){
                printf("\n Special characters are not allowed, Don't try to crash our programme!!!\n");
                return 0;
            }
        }
        printf("\n File Name is Proper and Accepted\n");
    }

/**************************** END of Command Line Arguments Parsing *********************************/

    fp = fopen(argv[0],"rb");
    if(fp > 0)
    {
        //FlagFileOpen =1;
        printf("FILE OPEN SUCCESSFUL!!!!!With Handler:%d\n",fp);

        //NOW, READ THE COMPLETE FILE CONTENT TO A LOCAL VARIABLE

        i = 24 + 16;

        fseek(fp,i,SEEK_SET);

        FrameLength = 54;

        for(j=0;j<54;j++)
        {
            FrameData[j] = fgetc(fp);
        }

        int x=ProcessFrame(FrameData,FrameLength);
        if(x==1)
            printf("\n packet Processed Successfully\n");
        else
            printf("\n Packet is not processed Successfully\n");
        printf("Copied");
    }
    else
    {

        printf("The PCAP File not able to Open\n");
        FlagFileOpen =0;

        return 0;
    }
    printf("!!!!EXITING...GOOD-BYE!!!!!\n");
    return 0;
}
