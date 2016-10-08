/*
		FUnctional Breakdown of Parser to Read .PCAP type of file created by TcpDUMP for analysis
*/

#define MACROS


// Library includes including pcap.h from libpcap library
#include <pcap.h>
//---------------
//---------------
//---------------
//---------------
//---------------


//Declaration of structures of Packet headers - ----
/* e.g.  Ethernet header */
struct ethernet {
        //---------------
//---------------
//---------------
//---------------
//---------------
};

/* IP header */
struct sniff_ip {
//---------------
//---------------
//---------------
//---------------
//---------------

        struct  src, dest;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */

struct sniff_tcp {
//---------------
//---------------
//---------------
//---------------
//---------------

};

////  FUNCTION DEFINITIONS for 
/*
 1. Open the PCAP file to read. Open another file for writing the parser output  (may be in parallel to std out)
 2. Function to sanitise / validate the input files.
   (a) (check the validity of type of file -  reqd to study the PCAP header struct)
   (b)  Verify the file header block for correct PCAP file type
   (c)  Check the Frame header before commencement for every packet ethernet frme for total num of bytes in packet
   (d)  Reader each packet and call function to extract indivial headers from packet

 3. Function to sanitize the input packet for correct type and lenght
   (a) receive input packet in pointer and length
   (b) strip individual header and parse into the header structure individually
   (c) verify the header length/checksum
   (d) call function to exctract data / validate and print the data from structure pointers

 4. Call function to check the headertype and extract relevant info 
    (a) Receive headers into individual structure pointer for Ethernet , IP and TCP headers
    (b) Validate/chack/Sanitise individual headers for expected information in header fields
    (c) extract relevant info of field from the individual headers and print the info. Print detailed info for TCP header. Print summary info of packet if UDP packet is received.
    (d) Write the all packet info to std out and output file including TCP payload .


 3. Functions to parse the read data from input file to populate the Packet headers structures and data  

 */


void function_readSanitiseInputfile() {
/*
Function to sanitise / validate the input files.
   (a) (check the validity of type of file -  reqd to study the PCAP header struct)
   (b)  Verify the file header block for correct PCAP file type
   (c)  Check the Frame header before commencement for every packet ethernet frme for total num of bytes in packet
   (d)  Reader each packet and call function to extract indivial headers from packet

 */
}





void function_extractHeadersFromPackets() {
/*

 Function to sanitize the input packet for correct type and lenght
   (a) receive input packet in pointer and length
   (b) strip individual header and parse into the header structure individually
   (c) verify the header length/checksum
   (d) call function to exctract data / validate and print the data from structure pointers
*/
}


void function_extractCheckHeaderInfo_writetoFile() {
/*

Call function to check the headertype and extract relevant info 
    (a) Receive headers into individual structure pointer for Ethernet , IP and TCP headers
    (b) Validate/chack/Sanitise individual headers for expected information in header fields
    (c) extract relevant info of field from the individual headers and print the info. Print detailed info for TCP header. Print summary info of packet if UDP packet is received.
    (d) Write the all packet info to std out and output file including TCP payload .
*/
}




int main(int argc, char **argv)
{


FILE f_in*;
FILE f_out*;

f_in = fopen("input_file", 'r');
f_in = fopen("output_file", 'w');


function_readSanitiseInputfile() 

function_extractHeadersFromPackets()

function_extractCheckHeaderInfo_writetoFile();

return 0;
}
