/********************************************************************************************
 *
 * CHECK_NRPE.C - NRPE Plugin For Nagios
 * Copyright (c) 1999-2003 Ethan Galstad (nagios@nagios.org)
 * License: GPL
 *
 * Last Modified: 01-28-2003
 *
 * Command line: CHECK_NRPE -H <host_address> [-p port] [-c command] [-to to_sec]
 *
 * Description:
 *
 * This plugin will attempt to connect to the NRPE daemon on the specified server and port.
 * The daemon will attempt to run the command defined as [command].  Program output and
 * return code are sent back from the daemon and displayed as this plugin's own output and
 * return code.
 *
 ********************************************************************************************/

#include "../common/common.h"
#include "../common/config.h"
#include "utils.h"

#define DEFAULT_NRPE_COMMAND	"_NRPE_CHECK"  /* check version of NRPE daemon */

int server_port=DEFAULT_SERVER_PORT;
char server_name[MAX_HOST_ADDRESS_LENGTH];

char query_string[MAX_PACKETBUFFER_LENGTH]=DEFAULT_NRPE_COMMAND;;
int socket_timeout=DEFAULT_SOCKET_TIMEOUT;

int show_help=FALSE;
int show_license=FALSE;
int show_version=FALSE;


int process_arguments(int,char **);
void alarm_handler(int);




int main(int argc, char **argv){
        u_int32_t long packet_crc32;
        u_int32_t calculated_crc32;
	int16_t result;
	int sd;
	int rc;
	packet send_packet;
	packet receive_packet;
	int bytes_to_send;
	int bytes_to_recv;

	result=process_arguments(argc,argv);

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE){

		if(result!=OK)
			printf("Incorrect command line arguments supplied\n");
                printf("\n");
		printf("NRPE Plugin for Nagios\n");
		printf("Copyright (c) 1999-2003 Ethan Galstad (nagios@nagios.org)\n");
		printf("Version: %s\n",PROGRAM_VERSION);
		printf("Last Modified: %s\n",MODIFICATION_DATE);
		printf("License: GPL\n");
		printf("\n");
	        }

	if(result!=OK || show_help==TRUE){

		printf("Usage: %s -H <host_address> [-p port] [-c command] [-to to_sec]\n",argv[0]);
		printf("\n");
		printf("Options:\n");
		printf(" <host_address> = The IP address of the host running the NRPE daemon\n");
		printf(" [port]         = The port on which the daemon is running - default is %d\n",DEFAULT_SERVER_PORT);
		printf(" [command]      = The name of the command that the remote daemon should run\n");
		printf(" [to_sec]       = Number of seconds before connection attempt times out.\n");
		printf("                  Default timeout is %d seconds\n",DEFAULT_SOCKET_TIMEOUT);
		printf("\n");
		printf("Note:\n");
		printf("This plugin requires that you have the NRPE daemon running on the remote host.\n");
		printf("You must also have configured the daemon to associate a specific plugin command\n");
		printf("with the [command] option you are specifying here.  Upon receipt of the\n");
		printf("[command] argument, the NRPE daemon will run the appropriate plugin command and\n");
		printf("send the plugin output and return code back to *this* plugin.  This allows you\n");
		printf("to execute plugins on remote hosts and 'fake' the results to make Nagios think\n");
		printf("the plugin is being run locally.\n");
		printf("\n");
	        }

	if(show_license==TRUE)
		display_license();

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE)
		exit(STATE_UNKNOWN);


        /* generate the CRC 32 table */
        generate_crc32_table();

	/* initialize alarm signal handling */
	signal(SIGALRM,alarm_handler);

	/* set socket timeout */
	alarm(socket_timeout);

	/* try to connect to the host at the given port number */
	result=my_tcp_connect(server_name,server_port,&sd);

	/* we connected, so close connection before exiting */
	if(result==STATE_OK){

		/* clear the packet buffer */
		bzero(&send_packet,sizeof(send_packet));

		/* fill the packet with semi-random data */
		randomize_buffer((char *)&send_packet,sizeof(send_packet));

		/* initialize packet data */
		send_packet.packet_version=(int16_t)htons(NRPE_PACKET_VERSION_2);
		send_packet.packet_type=(int16_t)htons(QUERY_PACKET);
		strncpy(&send_packet.buffer[0],query_string,MAX_PACKETBUFFER_LENGTH);
		send_packet.buffer[MAX_PACKETBUFFER_LENGTH-1]='\x0';

		/* calculate the crc 32 value of the packet */
		send_packet.crc32_value=(u_int32_t)0L;
		calculated_crc32=calculate_crc32((char *)&send_packet,sizeof(send_packet));
		send_packet.crc32_value=(u_int32_t)htonl(calculated_crc32);


		/***** ENCRYPT REQUEST *****/


		/* send the packet */
		bytes_to_send=sizeof(send_packet);
		rc=sendall(sd,(char *)&send_packet,&bytes_to_send);
		if(rc==-1){
			printf("CHECK_NRPE: Error sending query to host.\n");
			close(sd);
			return STATE_UNKNOWN;
		        }

		/* wait for the response packet */
		bytes_to_recv=sizeof(receive_packet);
		rc=recvall(sd,(char *)&receive_packet,&bytes_to_recv,socket_timeout);

		/* reset timeout and close the connection */
		alarm(0);
		close(sd);

		/* recv() error */
		if(rc<0){
			printf("CHECK_NRPE: Error receiving data from daemon.\n");
			return STATE_UNKNOWN;
		        }

		/* server disconnected */
		else if(rc==0){
			printf("CHECK_NRPE: Received 0 bytes from daemon.  Check the remote server logs for error messages.\n");
			return STATE_UNKNOWN;
		        }

		/* receive underflow */
		else if(bytes_to_recv<sizeof(receive_packet)){
			printf("CHECK_NRPE: Receive underflow - only %d bytes received (%d expected).\n",bytes_to_recv,sizeof(receive_packet));
			return STATE_UNKNOWN;
		        }

		
		/***** DECRYPT RESPONSE *****/


		/* check the crc 32 value */
		packet_crc32=ntohl(receive_packet.crc32_value);
		receive_packet.crc32_value=0L;
		calculated_crc32=calculate_crc32((char *)&receive_packet,sizeof(receive_packet));
		if(packet_crc32!=calculated_crc32){
			printf("CHECK_NRPE: Response packet had invalid CRC32.\n");
			close(sd);
			return STATE_UNKNOWN;
                        }
	
		/* get the return code from the remote plugin */
		result=(int16_t)ntohl(receive_packet.result_code);

		/* print the output returned by the daemon */
		receive_packet.buffer[MAX_PACKETBUFFER_LENGTH-1]='\x0';
		if(!strcmp(receive_packet.buffer,""))
			printf("CHECK_NRPE: No output returned from daemon.\n");
		else
			printf("%s\n",receive_packet.buffer);
	        }

	/* reset the alarm */
	else
		alarm(0);

	return result;
        }



/* process command line arguments */
int process_arguments(int argc, char **argv){
	int x;


	/* no options were supplied */
	if(argc<2)
		return ERROR;

	/* handle older style command line format - host address was first argument */
	strncpy(server_name,argv[1],sizeof(server_name)-1);
	server_name[sizeof(server_name)-1]='\x0';

	/* process all arguments */
	for(x=2;x<=argc;x++){

		if(!strcmp(argv[x-1],"-H")){
			if(x<argc){
				strncpy(server_name,argv[x],sizeof(server_name)-1);
				server_name[sizeof(server_name)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }
		else if(!strcmp(argv[x-1],"-c")){
			if(x<argc){
				strncpy(query_string,argv[x],sizeof(query_string)-1);
				query_string[sizeof(query_string)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }
		else if(!strcmp(argv[x-1],"-p")){
			if(x<argc){
				server_port=atoi(argv[x]);
				x++;
			        }
			else
				return ERROR;
		        }
		else if(!strcmp(argv[x-1],"-to")){
			if(x<argc){
				socket_timeout=atoi(argv[x]);
				if(socket_timeout<=0)
					return ERROR;
				x++;
			        }
			else
				return ERROR;
		        }
		else if(!strcmp(argv[x-1],"-h") || !strcmp(argv[x-1],"--help"))
			show_help=TRUE;
		else if(!strcmp(argv[x-1],"--license"))
			show_license=TRUE;
		else if(!strcmp(argv[x-1],"--version"))
			show_version=TRUE;
		else
			return ERROR;
	        }

	return OK;
        }



void alarm_handler(int sig){

	printf("CHECK_NRPE: Socket timeout after %d seconds.\n",socket_timeout);

	exit(STATE_CRITICAL);
        }
