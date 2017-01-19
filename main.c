#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include<sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define MAX_PCAP_FILE_SIZE 65536  //65536 BYTE
#define MAX_ETHERNET_FRAME_SIZE 1600//1560

#define FileHeaderLength 24
#define FrameHeaderLength 16
#define EscapeLength 8

#define ETHERNET 0x01

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

FILE *fdata =NULL;


//  Function Declaration Block

int CheckFrameLength(unsigned char* FrameHeader);
int CheckLinkLayerProtocol(unsigned char* FileHeader);
int CheckMagicNumber(unsigned char* FileHeader);
int CheckVersionNumber(unsigned char* FileHeader);
int ValidateFileName(int argc, char *argv[]);

int TCP_count=0;
int IP_count=0;
int ETH_count;
int BadTCPSegment=1;
int NonTCPCount=1;
int notIPpacket;

void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len, FILE *fdata);

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct IP_hdr {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->hl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

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

unsigned char MagicNumberLittleEndian[4] = {0xd4,0xc3,0xb2,0xa1};
unsigned char MagicNumberBigEndian[4] = {0xa1,0xb2,0xc3,0xd4};
unsigned char LibPcapMagicNumberLittleEndian[4] = {0x34,0xcd,0xb2,0xa1};
unsigned char LibPcapMagicNumberBigEndian[4] = {0xa1,0xb2,0xcd,0x34};

int FlagBigEndian,FlagLittleEndian;
int FlagLibPcapFile=0;

/* For Team review issue "Unused variables and dead code":
Function modified to remove the unused variable passed to the function as observed by the code review team - 19-01-2017
(The parameter removed from the function is: total_frame_len)
*/

// Function to Extract Ethernet Frame Data (Src / Destination MAC and Next level of Protocol (Accept only IP) )
//int Extract_Eth_header(struct ether_header  *Eth_hdr, unsigned int total_frame_len){ //Issue: unused parameter ‘total_frame_len’ [-Wunused-parameter]
int Extract_Eth_header(struct ether_header  *Eth_hdr){

    printf("\n**** Processing Ethernet Frame Header # %d\t ********\n", (ETH_count+1));
    printf("|-- Destinantion MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n", Eth_hdr->ether_dhost[0],Eth_hdr->ether_dhost[1], \
            Eth_hdr->ether_dhost[2],Eth_hdr->ether_dhost[3],Eth_hdr->ether_dhost[4],Eth_hdr->ether_dhost[5]);
    printf("|-- Source MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n", Eth_hdr->ether_shost[0],Eth_hdr->ether_shost[1], \
            Eth_hdr->ether_shost[2],Eth_hdr->ether_shost[3],Eth_hdr->ether_shost[4],Eth_hdr->ether_shost[5]);
    printf("|-- Next Header/Protocol Type: %04hx\n\n", ntohs(Eth_hdr->ether_type));

    // Write to outputfile

    fprintf(fdata,"\n****\tProcessing Ethernet Frame Header # %d\t********\n", (ETH_count+1));
    fprintf(fdata,"|-- Destinantion MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n", Eth_hdr->ether_dhost[0],Eth_hdr->ether_dhost[1], \
            Eth_hdr->ether_dhost[2],Eth_hdr->ether_dhost[3],Eth_hdr->ether_dhost[4],Eth_hdr->ether_dhost[5]);

    fprintf(fdata,"Source MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n", Eth_hdr->ether_shost[0],Eth_hdr->ether_shost[1], \
            Eth_hdr->ether_shost[2],Eth_hdr->ether_shost[3],Eth_hdr->ether_shost[4],Eth_hdr->ether_shost[5]);

    fprintf(fdata,"|-- Next Header/Protocol Type: %04hx\n\n", ntohs(Eth_hdr->ether_type));

    if (ntohs(Eth_hdr->ether_type) != 0x0800)
    {
        fprintf(fdata, "\nInvalid IP datagram Type detected\n ");
        notIPpacket++;
        return -1;
    }

    ETH_count++;
    // Issue: return is missing as observed in compilation with GCC -Wall -Wextra.
    return 1;
}

/* Team code review issue "Unused variables and dead code":
Function modified to remove the unused variable passed to the function as observed by the code review team - 19-01-2017
(The parameter removed from the function is: IP_header_len)
*/

// Function to Extract IP header Data
//int Extract_IPdata(struct ip *ip, int IP_header_len){ //Issue: unused parameter ‘IP_header_len’ [-Wunused-parameter]

int Extract_IPdata(struct ip *ip){
    unsigned int TCP_pack_len;
    int size_ip = ((ip->ip_hl)*4);
    //check for validation of IP header Size
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        fprintf(fdata,"   * Invalid IP header length: %u bytes\n", size_ip);

        return -1;
    }
    else {

        unsigned int IP_pack_len = ntohs(ip->ip_len);
        unsigned short chksum = ip->ip_sum;

        printf("|-- \n **** Processing IP Header*****\n");
        printf("|-- IP Ver : %u\t", ip->ip_v);
        printf("|-- IP header Length : %u bytes\n", (ip->ip_hl)*4);
        printf("|-- Type of Service : %u\n", ntohs(ip->ip_tos));
        printf("|-- IP Packet Length : %u\n", ntohs(ip->ip_len));
        printf("|-- IP Fragment Identifier : %u\n", (ip->ip_id));
        printf("|-- IP Fragment Offset(if present) : %u\n", (ip->ip_off));
        printf("|-- Next Protocol ID : 0x%02x\n", (ip->ip_p));
        printf("|-- TTL : %d\n", (ip->ip_ttl));
        printf("|-- Source IP : %s\n", inet_ntoa(ip->ip_src));
        printf("|-- Destination IP : %s\n", inet_ntoa(ip->ip_dst));
        printf("|-- IP Header Checksum : %u\n", chksum);

        // Write to IP header data outputfile

        fprintf(fdata,"|-- \n **** Processing IP Header*****\n");
        fprintf(fdata,"|-- IP Ver : %u\t", ip->ip_v);
        fprintf(fdata,"|-- IP header Length : %u bytes\n", (ip->ip_hl)*4);
        fprintf(fdata,"|-- Type of Service : %u\n", ntohs(ip->ip_tos));
        fprintf(fdata,"|-- IP Packet Length : %u\n", ntohs(ip->ip_len));
        fprintf(fdata,"|-- IP Fragment Identifier : %u\n", (ip->ip_id));
        fprintf(fdata,"|-- IP Fragment Offset(if present) : %u\n", (ip->ip_off));
        fprintf(fdata,"|-- Next Protocol ID : 0x%02x\n", (ip->ip_p));
        fprintf(fdata,"|-- TTL : %d\n", (ip->ip_ttl));
        fprintf(fdata,"|-- Source IP : %s\n", inet_ntoa(ip->ip_src));
        fprintf(fdata,"|-- Destination IP : %s\n", inet_ntoa(ip->ip_dst));
        fprintf(fdata,"|-- IP Header Checksum : %u\n", chksum);


        TCP_pack_len = IP_pack_len - ((ip->ip_hl)*4);
        IP_count++;                                     //increase counter for corrcectly processed IP header

        return TCP_pack_len;

    }

}

// Function to Extract TCP header Data

int Extract_TCPdata(struct TCP_hdr* tcp, unsigned int TCP_pack_len){

    printf("\n **** Processing TCP Header*****\n");
    fprintf(fdata,"\n **** Processing TCP Header*****\n");

    int size_tcp = TH_OFF(tcp)*4;

    //check for validation of TCP header Size
    if ((size_tcp < 20) ) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return 0;

    }

    else if ((size_tcp >=20))
    {

        printf("|-- TCP Header Size(Bytes) = %d\n", size_tcp);
        printf("|-- Src port : %d\n", ntohs(tcp->th_sport));
        printf("|-- Dst port : %d\n", ntohs(tcp->th_dport));
        printf("|-- Sequence Number : %u\n", ntohs(tcp->th_seq));
        printf("|-- Acknowledgement Number : %u\n", ntohs(tcp->th_ack));
        printf("|-- TCP Data Offset : %d\n",size_tcp);
        printf("|-- Flags : 0x%04x \n",tcp->th_flags);
        printf("|-- TCP Window Size : %u\n", ntohs(tcp->th_win));
        printf("|-- Checksum : 0x%4x\n", ntohs(tcp->th_sum));
        printf("|-- Urgent Field value : %u\n", ntohs(tcp->th_urp));

        // Write TCP header data to file

        fprintf(fdata, "|-- TCP Header Size(Bytes) = %d\n", size_tcp);
        fprintf(fdata, "|-- Src port : %d\n", ntohs(tcp->th_sport));
        fprintf(fdata, "|-- Dst port : %d\n", ntohs(tcp->th_dport));
        fprintf(fdata, "|-- Sequence Number : %u\n", ntohs(tcp->th_seq));
        fprintf(fdata, "|-- Acknowledgement Number : %u\n", ntohs(tcp->th_ack));
        fprintf(fdata, "|-- TCP Data Offset : %d\n",size_tcp);
        fprintf(fdata, "|-- Flags : 0x%04x \n",tcp->th_flags);
        fprintf(fdata, "|-- TCP Window Size : %u\n", ntohs(tcp->th_win));
        fprintf(fdata, "|-- Checksum : 0x%4x\n", ntohs(tcp->th_sum));
        fprintf(fdata, "|-- Urgent Field value : %u\n", ntohs(tcp->th_urp));

        /* define/compute tcp payload (segment) offset */
        unsigned char* payload;

        payload = (u_char *)(tcp + size_tcp);

        /* compute tcp payload (segment) size */
        int size_payload;
        size_payload =  (TCP_pack_len - size_tcp);
        printf("   App Payload Size %u\n", size_payload);

        // Call printing function to print Application/payload data in HEX and  ASCII Format ;

        if (size_payload > 0) {
            printf("   Application Payload (%d bytes):\n", size_payload);
            fprintf(fdata,"   Application Payload (%d bytes):\n", size_payload);

            print_payload(payload,size_payload, fdata);

        }
    TCP_count++;     //increase counter for corrcectly processed TCP header
    }

    return 1;
}

/*
Code modification for closing of issue "Comparison between signed vs unsigned integer" in line nos 292 & 311 below - 19-01-2017.
changed int Frame_Length to unsigned int Frame_Length in function call and defination.
*/

//int ProcessFrame(unsigned char *Frame_Data,int Frame_Length)  //Issue: Comparison between signed vs unsigned integer. - 19-01-2017.
int ProcessFrame(unsigned char *Frame_Data,unsigned int Frame_Length)
{
    int retValue, retEthValue;
    struct ether_header *Eth_hdr;
    struct ip *ip;
    struct TCP_hdr *tcp;
    unsigned int TCP_pack_len = 0;

    unsigned int IP_header_length;

    //int total_frame_len  = Frame_Length; //Issue: unused variable ‘total_frame_len’ [-Wunused-variable] -19-01-2017

    printf("\nProcessing Frame\n");

    // Ethernet Header Checking...
    if(Frame_Length < sizeof(struct ether_header)){
        printf("\n Packet size is less than Ethernet Header");
        return 0;
    }

    //printf("Frame_Header %x\n", Frame_Data);      //Issue: format ‘%x’ expects argument of type
                            //‘unsigned int’, but argument 2 has type ‘unsigned char *’ [-Wformat=]
    printf("Frame_Header %p\n", Frame_Data);

    Eth_hdr = (struct ether_header*) Frame_Data;
    retEthValue = Extract_Eth_header(Eth_hdr);
    if (retEthValue == -1)
        return 0;

    // Skipping Ethernet Header
    Frame_Data +=sizeof(struct ether_header);
    Frame_Length -=sizeof(struct ether_header);

    // IP Header Checking...
    if((Frame_Length < sizeof(struct ip))){
        printf("\n Malformed Packet : Packet Size is less than IP Header");
        fprintf(fdata,"\n Malformed Packet : Packet Size is less than IP Header");
        return 0;
    }

    ip = (struct ip*) Frame_Data;  // IP pointer
    IP_header_length = (ip->ip_hl) * 4;
    fprintf(fdata, "\n IP Header length  = %d -----%d", IP_header_length, (ip->ip_hl) * 4);

    // IP options Checking...
    if(Frame_Length < IP_header_length){
        printf("\n IP Header length invalid/improper");
        fprintf(fdata, "\n IP Header length invalid/improper");
        return 0;

    }

    else {

        // Calll function to extract data from IP header and return TCP_pack_Len

        TCP_pack_len = Extract_IPdata(ip);
        printf("\nTCP_pack_Len = %u \t \t IP_count = %d\n",TCP_pack_len,IP_count);
        fprintf(fdata, "\nTCP_pack_Len = %u \t \t IP_count = %d\n",TCP_pack_len,IP_count);

    }

    // Checking for Non TCP Packets...
    if(ip->ip_p != IPPROTO_TCP)
    {
        NonTCPCount++;
        if(NonTCPCount==0)
        {
            printf("\n The NonTCPCount Counter excedded its limit\n");
            return 0;
        }

        printf("\n This is not a TCP Packet\n");
        return 1;
    }

    // Skipping IP Header to TCP Header
    Frame_Data +=IP_header_length;
    Frame_Length -= IP_header_length;

    // TCP header Checking....
    if(Frame_Length < sizeof(struct TCP_hdr)){
        printf("\n Packet size is less than TCP Header\n");
        return 0;
    }


    tcp=(struct TCP_hdr*) Frame_Data;

    retValue = Extract_TCPdata(tcp, TCP_pack_len);

// Calll function to extract data from TCP header and check for retValue for Bad/Malformed TCP segment
    if (retValue !=1)
    {
        BadTCPSegment++;
        if(BadTCPSegment==0)
        {
            printf("\n The BadTCPSegment Counter excedded its limit\n");
            return 0;
        }
        printf("Error Processing TCP header");
        return 0;
    }

    else
        return 1;
}

//The Main Function
int main(int argc, char *argv[])
{
    //int i;                // Issue: comparison between signed and unsigned integer expression.
    unsigned int i;
    //Total Frames analysed
    int TotalFrame=1;
    //Total Frames escaped
    int FrameEscape=1;
    //Total Error Frames
    int ErrorFrameCounter=1;
    unsigned char ch;
    //int Frame_Protocol,FrameLength; // Code Review Issue: Comparison of signed vs unsigned. -19-01-2017
    unsigned int Frame_Protocol,FrameLength; // Corrected unsigned declaration.
    //The pointers for collecting the various important data
    unsigned char *FileHeader,*FrameHeader,*FrameData;


    //File pointer
    FILE *fp=NULL;

    //ArgvQuote (const std::wstring& Argument,std::wstring& CommandLine,bool Force)

    //ArgvQuote (& argv[0],std::wstring& CommandLine,bool Force);


    //The validation of input parameters
    if(ValidateFileName(argc, argv)==1)
    {
        //once validation of input parameter done,
        //Do the normal tasks,

        //Opening file for parser data,
        fdata = fopen("parserdata.txt","w");
        if (fdata==NULL)
        {
            printf("file to write not found");
            exit(1);
        }

        //Opening the file as per input parameter,
        fp = fopen(argv[1],"rb");

/*
Code modification for closing of issue of "ordered comparison of pointer with integer zero" using -Wextra in GCC - 19-01-2017.

*/

        //The condition, the file handler has to be more than 0, which is usual secenario,
        //if(fp > 0) // Issue: ordered comparison of pointer with integer zero [-Wextra] - 19-01-2017.
        if(fp == NULL)
        {
            printf("\nThe PCAP File could not open successfully");
            exit(1);
        }
        else
        {
            printf("Input FILE OPEN SUCCESSFUL!!!!!\n");

            //Malloc for dynamic allocation of memory
            FileHeader = (unsigned char *)malloc(100);
            FrameHeader = (unsigned char *)malloc(100);
            FrameData = (unsigned char *)malloc (MAX_ETHERNET_FRAME_SIZE);

            //Setting file pointer at the start of file
            fseek(fp,0,SEEK_SET);
            //Readig the File Header
            for(i =0;i<FileHeaderLength;i++)
            {
                FileHeader[i] = fgetc(fp);
            }
            //Checking the magic number, present in the file or not
            if(CheckMagicNumber(FileHeader) == 1)
            {
                printf("THIS IS VALID PCAP FILE!!!!!\n");

                //Displays the version number
                CheckVersionNumber(FileHeader);

                //The link layer protocol, can be PoE, Ethernet.. Restricting code to do only for ETHERNET
                Frame_Protocol = CheckLinkLayerProtocol(FileHeader);

                if(Frame_Protocol==ETHERNET)
                {
                    printf("The Frame Protocol: %x \n",Frame_Protocol);

                    //We finished with File Header, Now focusing on Frames,
                    //Reading the Frame Header
                    for(i=0;i<FrameHeaderLength;i++)
                    {
                        FrameHeader[i] = fgetc(fp);
                    }
                    do
                    {
                        //This is to get and check the FrameLength
                        FrameLength = CheckFrameLength(FrameHeader);

                        //For LibPcap file, escaping the 8 bytes, to get the FrameHeader
                        if(FlagLibPcapFile==1)
                        {
                            for(i=0;i<EscapeLength;i++)
                            {
                                ch = fgetc(fp);
                            }
                        }
                        //Counting the Total Frames analysed and reporting when it exceeds its limit
                        TotalFrame++;
                        if(TotalFrame==0)
                        {
                            printf("\n The TotalFrame Counter excedded its limit\n");
                            return 0;
                        }
                        //Allowing the FrameLength less than or equal to MAX Ethernet Frame Size
                        if(FrameLength <= MAX_ETHERNET_FRAME_SIZE)
                        {
                            //Reading the FrameHeader,
                            for(i=0;i<FrameLength;i++)
                            {
                                FrameData[i] = fgetc(fp);
                            }
                            //Passing the FrameData and its length for processing
                            i = ProcessFrame(FrameData,FrameLength);
                            //For any ambiguity, the processFrame returns 0, else 1. For 0 stop reading the file further and terminating the code
                            if( (i==1) || (i==0) )
                            {
                                //This is to count the Error Frame might have corrupted data
                                if(i==0)
                                {
                                    printf("\nThe previous frame was not good...Going for next Frame\n");
                                    ErrorFrameCounter++;
                                    if(ErrorFrameCounter==0)
                                    {
                                        printf("\n The ErrorFrameCounter excedded its limit\n");
                                        return 0;
                                    }
                                }
                                else
                                {
                                    printf("\nThe previous frame was processed...Going for next Frame\n");
                                }
                                //Hunt for next Frame in the file
                                for(i=0;i<FrameHeaderLength;i++)
                                {
                                    FrameHeader[i] = fgetc(fp);
                                }

                                //The file END is detected using this method,
                                if( (FrameHeader[0]==0xFF) && (FrameHeader[1]==0xFF) && (FrameHeader[2]==0xFF) && (FrameHeader[3]==0xFF) )
                                {
                                    //printf("\nFILE ENDED\n");
                                    ch = 0xFF;
                                }
                                //If file is not ended, copy next Frame
                            }
                            else
                            {
                                printf("\n Packet is not processed Successfully\n");
                                ch = 0xFF;
                                printf("\nExiting Because Packet Processing Failed!!!\n");
                            }
                        }
                        else
                        {
                            //when the frame is more than MAX Ethernet Frame Size, do nothing skip it and go to next

                            printf("\nFrameLength is more than %d bytes..Escaping\n",MAX_ETHERNET_FRAME_SIZE);

                            FrameEscape++;
                            if(FrameEscape==0)
                            {
                                printf("\n The FrameEscape Counter excedded its limit\n");
                                return 0;
                            }
		// Issue #4 raised code review (Team B) - correction done on 19.01.2017
		// Logical assumption of FrameLength being correct in file for all frames may not be correct for a malformed/fuzzed file.
		// therefore, Escaping the current frame being processed to jump to next frame is not possible.
		// and hence, further parsing of the input file is discontinued (code commented below) and progame exit gracefully. 
                            /*//Just rotating the fp counter to the next frame header,
                            for(i=0;i<FrameLength;i++)
                            {
                                ch = fgetc(fp);
                            }
                            //Reading the frame
                            for(i=0;i<FrameHeaderLength;i++)
                            {
                                FrameHeader[i] = fgetc(fp);
                            }

                            //The file END is detected using this method,
                            if( (FrameHeader[0]==0xFF) && (FrameHeader[1]==0xFF) && (FrameHeader[2]==0xFF) && (FrameHeader[3]==0xFF) )
                            {
                                //printf("\nFILE ENDED\n");
                                ch = 0xFF;
                            }*/
		//Correction for gracefull exiting of program on detection of incorrect value of framelength - 19.01.2017
				ch = 0xFF; 
				printf("\n Found corrupted Frame Length and exiting the program now!!! \n");

                        }
                    }while(ch!=0xFF); //The condition is to check the end of file

                    printf("FILE ENDED with 0xFF \n");
                    printf("\n\n****** SUMMARY OF PARSER DATA %s*************\n", argv[1]);
                    printf("\n TotalFrame=%d \t FrameEscape= %d \t Total ErrorFrameCounter = %d\n ",TotalFrame-1,FrameEscape-1, ErrorFrameCounter-1);
                    printf("Total Frames Analysed = %d\n Total valid IP Packets Processed = %d \t Total Invalid IP datagrams = %d \n Valid TCP Segments Processed= %d \t Total NonTCP Segments= %d \tTotal BadTCPSegment = %d \n\n", ETH_count, IP_count,notIPpacket, TCP_count,NonTCPCount-1,BadTCPSegment-1);


                    //Writing to file
                    fprintf(fdata,"FILE ENDED with 0xFF \n");
                    fprintf(fdata,"\n\n****** SUMMARY OF PARSER DATA %s *************\n", argv[1]);
                    fprintf(fdata,"\n TotalFrame=%d \t FrameEscape= %d \t Total ErrorFrameCounter = %d\n ",TotalFrame-1,FrameEscape-1, ErrorFrameCounter-1);
                    fprintf(fdata,"Total Frames Analysed = %d\n Total valid IP Packets Processed = %d \t Total Invalid IP datagrams = %d \n Valid TCP Segments Processed= %d \t Total NonTCP Segments= %d \tTotal BadTCPSegment = %d \n\n", ETH_count, IP_count,notIPpacket, TCP_count,NonTCPCount-1,BadTCPSegment-1);

                }//End of if for ETHERNET
            }
            else
            {
                printf("Not Valid PCAP/CAP file....Exiting....\n");
                //return 0;
            }

            //Free the malloc memories
                free(FileHeader);
                free(FrameData);
                free(FrameHeader);

            //Closing the files
                fclose(fdata);
                fclose(fp);
        }
        /*else
        {
            printf("The PCAP File not able to Open\n");
            return 0;
        }*/
    }
    else
    {
        printf("\n File Name Validation Failed!!!!\n");
        return 0;
    }

    printf("!!!!EXITING...GOOD-BYE!!!!!\n");
    return 0;
}
