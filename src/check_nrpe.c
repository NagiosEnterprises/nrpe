/********************************************************************************************
 *
 * CHECK_NRPE.C
 *
 * Program: NRPE plugin for Nagios
 * License: GPL
 * Copyright (c) 1999-2002 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 02-21-2002
 *
 * Command line: CHECK_NRPE <host_address> [-p port] [-c command] [-wt warn_time] \
 *                          [-ct crit_time] [-to to_sec]
 *
 * Description:
 *
 * This plugin will attempt to connect to the Nagios remote plugin executor daemon on the
 * specified server and port.  The daemon will attempt to run the command defined as
 * [command].  Program output and return code are sent back from the daemon and displayed
 * as this plugin's own output and return code.
 *
 ********************************************************************************************/

#include "../common/common.h"
#include "../common/config.h"
#include "netutils.h"

#define DEFAULT_NRPE_COMMAND	"_NRPE_CHECK"  /* check version of NRPE daemon */

int server_port=DEFAULT_SERVER_PORT;
char server_name[MAX_HOST_ADDRESS_LENGTH];

char query_string[MAX_PACKETBUFFER_LENGTH]=DEFAULT_NRPE_COMMAND;;
int socket_timeout=DEFAULT_SOCKET_TIMEOUT;



int process_arguments(int,char **);
void alarm_handler(int);




int main(int argc, char **argv){
	int sd;
	int rc;
	int result;
	packet send_packet;
	packet receive_packet;
	int bytes_to_send;
	int bytes_to_recv;

	result=process_arguments(argc,argv);

	if(result!=OK){

		printf("Incorrect command line arguments supplied\n");
		printf("\n");
		printf("NRPE Plugin for Nagios\n");
		printf("Copyright (c) 1999-2002 Ethan Galstad (nagios@nagios.org)\n");
		printf("Version: %s\n",PROGRAM_VERSION);
		printf("Last Modified: %s\n",MODIFICATION_DATE);
		printf("License: GPL\n");
		printf("\n");
		printf("Usage: %s <host_address> [-p port] [-c command] [-wt warn_time]\n",argv[0]);
		printf("          [-ct crit_time] [-to to_sec]\n");
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

		return STATE_UNKNOWN;
	        }

	/* initialize alarm signal handling */
	signal(SIGALRM,alarm_handler);

	/* set socket timeout */
	alarm(socket_timeout);

	/* try to connect to the host at the given port number */
	result=my_tcp_connect(server_name,server_port,&sd);

	/* we connected, so close connection before exiting */
	if(result==STATE_OK){

		/* send the query packet */
		bzero(&send_packet,sizeof(send_packet));
		send_packet.packet_type=htonl(QUERY_PACKET);
		send_packet.packet_version=htonl(NRPE_PACKET_VERSION_1);
		send_packet.buffer_length=htonl(strlen(query_string));
		strcpy(&send_packet.buffer[0],query_string);

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

		/* recv() error */
		if(rc<0){
			printf("CHECK_NRPE: Error receiving data from host.\n");
			close(sd);
			alarm(0);
			return STATE_UNKNOWN;
		        }

		/* server disconnected */
		else if(rc==0){
			printf("CHECK_NRPE: Received 0 bytes.  Are we allowed to connect to the host?\n");
			close(sd);
			alarm(0);
			return STATE_UNKNOWN;
		        }

		/* receive underflow */
		else if(bytes_to_recv<sizeof(receive_packet)){
			printf("CHECK_NRPE: Receive underflow - only %d bytes received (%d expected).\n",bytes_to_recv,sizeof(receive_packet));
			close(sd);
			alarm(0);
			return STATE_UNKNOWN;
		        }

		/* get the return code from the remote plugin */
		result=ntohl(receive_packet.result_code);

		/* make sure there is something in the plugin output buffer */
		if(!strcmp(receive_packet.buffer,""))
			printf("CHECK_NRPE: No output returned from NRPE daemon.\n");
		else
			printf("%s\n",receive_packet.buffer);

		/* close the connection */
		close(sd);
	        }

	/* reset the alarm */
	alarm(0);

	return result;
        }



/* process command line arguments */
int process_arguments(int argc, char **argv){
	int x;


	/* no options were supplied */
	if(argc<2)
		return ERROR;

	/* first option is always the server name/address */
	strncpy(server_name,argv[1],sizeof(server_name)-1);
	server_name[sizeof(server_name)-1]='\x0';

	/* process all remaining arguments */
	for(x=3;x<=argc;x++){

		if(!strcmp(argv[x-1],"-c")){
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
		else
			return ERROR;
	        }

	return OK;
        }



void alarm_handler(int sig){

	printf("CHECK_NRPE: Socket timeout after %d seconds.\n",socket_timeout);

	exit(STATE_CRITICAL);
        }
