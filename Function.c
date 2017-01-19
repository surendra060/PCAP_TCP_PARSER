#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#define MAX_PCAP_FILE_SIZE 65536  //65536 BYTE
#define MAX_ETHERNET_FRAME_SIZE 1600//1560
#define ETHERNET 0x01

extern int CheckFrameLength(unsigned char* FrameHeader);
extern int CheckLinkLayerProtocol(unsigned char* FileHeader);
extern int CheckMagicNumber(unsigned char* FileHeader);
extern int CheckVersionNumber(unsigned char* FileHeader);

extern int ValidateFileName(int argc, char *argv[]);

extern unsigned char MagicNumberLittleEndian[4];
extern unsigned char MagicNumberBigEndian[4];
extern int FlagBigEndian,FlagLittleEndian;
extern unsigned char LibPcapMagicNumberLittleEndian[4];
extern unsigned char LibPcapMagicNumberBigEndian[4];
extern int FlagLibPcapFile;

//extern FILE *fdata;

//************************************Extracting the Frame Length************************************
int CheckFrameLength(unsigned char* FrameHeader)
{
    //int i,FrameLength,FrameLength1,FrameLength2; //   Unintilized variables pointed by Code Review - Initialized below 19-1-17
    int i=0,FrameLength=0,FrameLength1=0,FrameLength2=0;
    i = 8;    

    if(FlagBigEndian == 1)
    {
        FrameLength1 = FrameHeader[i+3] + (FrameHeader[i+2] << 8) + (FrameHeader[i+1] << 16) + (FrameHeader[i] << 24);
        printf("FrameLength1: %d \n",FrameLength1);        
    }

    if(FlagLittleEndian == 1)
    {
        FrameLength1 = FrameHeader[i] + (FrameHeader[i+1] << 8) + (FrameHeader[i+1+1] << 16) + (FrameHeader[i+1+1+1] << 24);
        printf("FrameLength1: %d \n",FrameLength1);        
    }

    i = 8 + 4;
    if(FlagBigEndian == 1)
    {
        FrameLength1 = FrameHeader[i+3] + (FrameHeader[i+2] << 8) + (FrameHeader[i+1] << 16) + (FrameHeader[i] << 24);
        printf("FrameLength2: %d \n",FrameLength2);        
    }

    if(FlagLittleEndian == 1)
    {
        FrameLength2 = FrameHeader[i] + (FrameHeader[i+1] << 8) + (FrameHeader[i+2] << 16) + (FrameHeader[i+3] << 24);
        printf("FrameLength2: %d \n",FrameLength2);
    }

    if(FrameLength1 >= FrameLength2)
        FrameLength = FrameLength1;
    else
        FrameLength = FrameLength2;

    return FrameLength;
}
//************************************Display the LinkLayer Protocol************************************
int CheckLinkLayerProtocol(unsigned char* FileHeader)
{
    int i=0,Protocol=0;     //   Unintilized variables pointed by Code Review - Initialized Now -17 Jan 17
//the 20,21,22,23 byte location will tell the Protocol

    i=20;

    if(FlagLittleEndian==1)
    {
        Protocol = FileHeader[i] + (FileHeader[i+1] << 8) + (FileHeader[i+2] << 16) + (FileHeader[i+3] << 24);
    }

    if(FlagBigEndian==1)
    {
        Protocol = FileHeader[i+3] + (FileHeader[i+2] << 8) + (FileHeader[i+1] << 16) + (FileHeader[i] << 24);
    }
    return Protocol;
}

//************************************Display the Version Number************************************
int CheckVersionNumber(unsigned char* FileHeader)
{
    int i=0;   //   Unintilized variables pointed by Code Review - Initialized Now -17 Jan 17
    int MajorVersion=0,MinorVersion=0; //   Unintilized variables pointed by Code Review - Initialized Now -17 Jan 17
//The 4,5,6 and 7 th bytes for version number, 4-5 for major number, 6-7 for minor number
    i =4;

    if(FlagLittleEndian == 1)
    {
        MajorVersion = FileHeader[i] + (FileHeader[i+1] << 8);
        MinorVersion = FileHeader[i+1+1] + (FileHeader[i+1+1+1] << 8);
    }

    printf("MajorVersion: %x MinorVersion:%x \n",MajorVersion,MinorVersion);

    if(FlagBigEndian == 1)
    {
        MajorVersion = FileHeader[i+1] + (FileHeader[i] << 8);
        MinorVersion = FileHeader[i+1+1+1] + (FileHeader[i+1+1] << 8);
    }
    return 0;
}
//************************************Validation of Magic Number************************************
int CheckMagicNumber(unsigned char* FileHeader)
{
    int i;

//The file should start with magic number

    FlagLittleEndian=1;
    FlagLibPcapFile=2;

    printf("Checking For Little Endian\n");
//First validating for Little Endian Processor
    for(i=0;i<4;i++)
    {
//Comparing with the known magic number
        if(MagicNumberLittleEndian[i] != FileHeader[i])
        {
            printf("NOT Little Endian \n");
            FlagLittleEndian=0;
            FlagLibPcapFile=0;
            break;
        }
    }
//If magic number not matched for Little Endiand,
//check for Big endian
    if(FlagLittleEndian == 0)
    {
        printf("Checking For BIG ENDIAN \n");

        FlagBigEndian = 1;
        FlagLibPcapFile=2;

        for(i=0;i<4;i++)
        {
            if(MagicNumberBigEndian[i] != FileHeader[i])
            {
                printf("NOT Big Endian\n");
                FlagBigEndian = 0;
                FlagLibPcapFile=0;
                break;
            }
        }
    }

    if((FlagLittleEndian == 0) && (FlagBigEndian == 0) )
    {
        printf(" Checking for LIB-PCAP FILE....\n");

        FlagLittleEndian=1;
//The flag indicates the file is LibPcap
        FlagLibPcapFile=1;

        printf("Checking For Little Endian\n");

        for(i=0;i<4;i++)
        {
            //Comparing with LibPcap magic numer
            if(LibPcapMagicNumberLittleEndian[i] != FileHeader[i])
            {
                printf("NOT Little Endian \n");
                FlagLittleEndian=0;
                FlagLibPcapFile=0;
                break;
            }
        }
//If magic number not matched for Little Endiand,
//check for Big endian

        if(FlagLittleEndian == 0)
        {
            printf("Checking For BIG ENDIAN \n");

            FlagBigEndian = 1;

            FlagLibPcapFile=1;

            for(i=0;i<4;i++)
            {
                if(LibPcapMagicNumberBigEndian[i] != FileHeader[i])
                {
                    printf("NOT Big Endian\n");
                    FlagBigEndian = 0;
                    FlagLibPcapFile=0;
                    break;
                }
            }
        }
    }

//Return the value based on validation
    if((FlagLittleEndian == 1) || (FlagBigEndian == 1) )
    {
        //printf("IT IS VALID PCAP\n");

        if(FlagLittleEndian == 1)
        {
            printf("It is Little Endian\n");
            FlagBigEndian=0;
            return 1;
        }
        else
        {
            printf("It is Big Endian\n");
            FlagLittleEndian=0;
            return 1;
        }
    }
    else
    {
        printf("NOT VALID PCAP FILE\n");
        return 0;
    }
}

//************************************Printing of Application Data  to Screen / File************************************


extern void
print_hex_ascii_line(const u_char *payload, int len, int offset, FILE *fdata)
{

    int i=0;
    int gap=0;   //   Unintilized variables pointed by Code Review - Initialized Now -17 Jan 17
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);
    fprintf(fdata, "%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");
        fprintf(fdata, " ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
            fprintf(fdata, " ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
        {
            printf("%c", *ch);
            fprintf(fdata, "%c", *ch);
        }
        else
        {
            printf(".");
            fprintf(fdata, ".");
        }
        ch++;
    }

    printf("\n");
    fprintf(fdata, "\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
extern void
print_payload(const u_char *payload, int len, FILE *fdata)
{

    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset, fdata);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset, fdata);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset, fdata);

            break;
        }
    }

return;
}

//************************************File Name Validation************************************

//To skip the Programm Name
 int ValidateFileName(int argc, char *argv[])
 {
     int i=0,special_flag=0,arglen=0;   //   Unintilized variables pointed by Code Review - Initialized Now -17 Jan 17

     int arg_max_length=25;


    ++argv;--argc;

    // No.of command line arguments checking and restricting to only one argument.
    if(argc < 1)
    {
        printf("\n Programm Requires one Argument (Eneter input PCAP file name)..!!\n");
        return 0;
    }
    else if(argc>1){
        printf("\n Too many Arguments, Programme Accepts only one Argument. Bye!!\n");
        return 0;
    }
    else{
            arglen=strlen(argv[0]);

        //File name length checking.
        if(arglen >=arg_max_length-1){
            printf("\n File name is too big, Don't try to crash our programme!!!\n");
            return 0;
        }
        //argv[arg_max_length]= '\0';

        //Special character checking in file name.
        //special_flag=0;  //   Unintilized variables pointed by Code Review - Initialized Now -17 Jan 17
        for(i=0;i<arglen;i++)
        {
            printf("%c",argv[0][i]);

            switch(argv[0][i])
            {
                case '\\':  printf("\n Back slash is detected, It is not allowed in File-name.\n");
                    special_flag=1;
                    break;
                case '$':  printf("\n Back slash is detected, It is not allowed in File-name.\n");
                    special_flag=1;
                    break;
                case '#':  printf("\n Back slash is detected, It is not allowed in File-name.\n");
                    special_flag=1;
                    break;
                case '%':  printf("\n Back slash is detected, It is not allowed in File-name.\n");
                    special_flag=1;
                    break;
                case '^':  printf("\n Back slash is detected, It is not allowed in File-name.\n");
                    special_flag=1;
                    break;
                case '\|':  printf("\n Back slash is detected, It is not allowed in File-name.\n");
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
                case ' ':   printf("\n Space is detected, It is not allowed in File-name.\n");
                    special_flag=1;
                    break;

                // we can add more speical characters here, if any.
            }
            if(special_flag==1){
                printf("\n Special characters are not allowed, Don't try to crash our programme!!!\n");
                return 0;
            }
        }
        printf("\n File Name is Proper and Accepted\n");
         return 1;
    }
 }
