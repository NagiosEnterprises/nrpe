/*******************************************************************************
 *
 * NRPE.C - Nagios Remote Plugin Executor
 * Copyright (c) 1999-2003 Ethan Galstad (nagios@nagios.org)
 * License: GPL
 *
 * Last Modified: 01-07-2003
 *
 * Command line: nrpe -c <config_file> [--inetd | --daemon]
 *
 * Description:
 *
 * This program is designed to run as a background process and
 * handle incoming requests (from the host running Nagios) for
 * plugin execution.  It is useful for running "local" plugins
 * such as check_users, check_load, check_disk, etc. without
 * having to use rsh or ssh.
 * 
 ******************************************************************************/

#include "../common/common.h"
#include "../common/config.h"
#include "nrpe.h"
#include "utils.h"

#define DEFAULT_COMMAND_TIMEOUT	60			/* default timeout for execution of plugins */
#define MAXFD                   64


int process_arguments(int,char **);

void wait_for_connections(void);
void handle_connection(int);
int read_config_file(char *);
int add_command(char *,char *);
command *find_command(char *);
void sighandler(int);
int drop_privileges(char *,char *);
void free_memory(void);
int is_an_allowed_host(char *);

int my_system(char *,int,int *,char *,int);            	/* executes a command via popen(), but also protects against timeouts */
void my_system_sighandler(int);				/* handles timeouts when executing commands via my_system() */


char    config_file[MAX_INPUT_BUFFER]="nrpe.cfg";
char    allowed_hosts[MAX_INPUT_BUFFER];
int     server_port=DEFAULT_SERVER_PORT;
char    server_address[16]="0.0.0.0";
int     socket_timeout=DEFAULT_SOCKET_TIMEOUT;
int     command_timeout=DEFAULT_COMMAND_TIMEOUT;

command *command_list=NULL;

char    *nrpe_user=NULL;
char    *nrpe_group=NULL;

int     show_help=FALSE;
int     show_license=FALSE;
int     show_version=FALSE;
int     use_inetd=TRUE;
int     debug=FALSE;



int main(int argc, char **argv){
	int error=FALSE;
	int result;
	int i;
	char buffer[MAX_INPUT_BUFFER];

	result=process_arguments(argc,argv);

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE){

		printf("\n");
		printf("NRPE - Nagios Remote Plugin Executor\n");
		printf("Copyright (c) 1999-2003 Ethan Galstad (nagios@nagios.org)\n");
		printf("Version: %s\n",PROGRAM_VERSION);
		printf("Last Modified: %s\n",MODIFICATION_DATE);
		printf("License: GPL\n");
		printf("\n");
	        }

	if(result!=OK || show_help==TRUE){

		printf("Usage: %s -c <config_file> [mode]\n",argv[0]);
		printf("\n");
		printf("Options:\n");
		printf(" <config_file> = Name of config file to use\n");
		printf(" [mode]        = Determines how NRPE should run. Valid modes:\n");
		printf("   --inetd     = Run as a service under inetd or xinetd\n");
		printf("   --daemon    = Run as a standalone daemon\n");
		printf("\n");
		printf("Notes:\n");
		printf("This program is designed to process requests from the check_nrpe\n");
		printf("plugin on the host(s) running Nagios.  It can run as a service\n");
		printf("under inetd or xinetd (read the docs for info on this), or as a\n");
		printf("standalone daemon. Once a request is received from an authorized\n");
		printf("host, NRPE will execute the command/plugin (as defined in the\n");
		printf("config file) and return the plugin output and return code to the\n");
		printf("check_nrpe plugin.\n");
		printf("\n");
		}

	if(show_license==TRUE)
		display_license();

        if(result!=OK || show_help==TRUE || show_license==TRUE || show_version==TRUE)
		exit(STATE_UNKNOWN);


	/* open a connection to the syslog facility */
        openlog("nrpe",LOG_PID,LOG_DAEMON); 

	/* make sure the config file uses an absolute path */
	if(config_file[0]!='/'){

		/* save the name of the config file */
		strncpy(buffer,config_file,sizeof(buffer));
		buffer[sizeof(buffer)-1]='\x0';

		/* get absolute path of current working directory */
		strcpy(config_file,"");
		getcwd(config_file,sizeof(config_file));

		/* append a forward slash */
		strncat(config_file,"/",sizeof(config_file)-2);
		config_file[sizeof(config_file)-1]='\x0';

		/* append the config file to the path */
		strncat(config_file,buffer,sizeof(config_file)-strlen(config_file)-1);
		config_file[sizeof(config_file)-1]='\x0';
	        }

	/* read the config file */
	result=read_config_file(config_file);	

	/* exit if there are errors... */
	if(result==ERROR){
		syslog(LOG_ERR,"Config file '%s' contained errors, bailing out...",config_file);
		return STATE_CRITICAL;
		}

	/* if we're running under inetd... */
	if(use_inetd==TRUE)
		handle_connection(0);

	/* else daemonize and start listening for requests... */
	else if(fork()==0){

		/* We are in the 1st child, become session leader */
		setsid();

		/* ignore SIGHUP */
		signal(SIGHUP, SIG_IGN);

		/* fork again, 1st child exits */
		if(fork()!=0)
			exit(0);

		/* grandchild process continues... */
	  
		chdir("/");
		umask(0);

		/* drop privileges */
		drop_privileges(nrpe_user,nrpe_group);

		/* wait for connections */
		wait_for_connections();
	        }

	/* We are now running in daemon mode, or the connection handed over by inetd has
	   been completed, so the parent process exits */
        return STATE_OK;
	}




/* read in the configuration file */
int read_config_file(char *filename){
	FILE *fp;
	char input_buffer[MAX_INPUT_BUFFER];
	char *temp_buffer;
	char *varname;
	char *varvalue;
	int line;


	/* open the config file for reading */
	fp=fopen(filename,"r");

	/* exit if we couldn't open the config file */
	if(fp==NULL){
		syslog(LOG_ERR,"Unable to open config file '%s' for reading\n",filename);
		return ERROR;
	        }

	line=0;
	while(fgets(input_buffer,MAX_INPUT_BUFFER-1,fp)){

		line++;

		/* skip comments and blank lines */
		if(input_buffer[0]=='#')
			continue;
		if(input_buffer[0]=='\x0')
			continue;
		if(input_buffer[0]=='\n')
			continue;

		/* get the variable name */
		varname=strtok(input_buffer,"=");
		if(varname==NULL){
			syslog(LOG_ERR,"No variable name specified in config file '%s' - Line %d\n",filename,line);
			return ERROR;
		        }

		/* get the variable value */
		varvalue=strtok(NULL,"\n");
		if(varvalue==NULL){
			syslog(LOG_ERR,"No variable value specified in config file '%s' - Line %d\n",filename,line);
			return ERROR;
		        }

		if(!strcmp(varname,"server_port")){
			server_port=atoi(varvalue);
			if(server_port<1024){
				syslog(LOG_ERR,"Invalid port number specified in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
		        }

                else if(!strcmp(varname,"server_address")){
                        strncpy(server_address,varvalue,sizeof(server_address) - 1);
                        server_address[sizeof(server_address) - 1] = '\0';
                        }

		else if(!strcmp(varname,"allowed_hosts")){
			if(strlen(input_buffer)>sizeof(allowed_hosts)){
				syslog(LOG_ERR,"Allowed hosts list too long in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
			strncpy(allowed_hosts,varvalue,sizeof(allowed_hosts));
			allowed_hosts[sizeof(allowed_hosts)-1]='\x0';
		        }

		else if(strstr(input_buffer,"command[")){
			temp_buffer=strtok(varname,"[");
			temp_buffer=strtok(NULL,"]");
			if(temp_buffer==NULL){
				syslog(LOG_ERR,"Invalid command specified in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
			add_command(temp_buffer,varvalue);
		        }

		else if(strstr(input_buffer,"debug")){
			debug=atoi(varvalue);
			if(debug>0)
				debug=TRUE;
			else 
				debug=FALSE;
		        }

                else if(!strcmp(varname,"nrpe_user"))
			nrpe_user=strdup(varvalue);

                else if(!strcmp(varname,"nrpe_group"))
			nrpe_group=strdup(varvalue);
		
		else if(!strcmp(varname,"command_timeout")){
			command_timeout=atoi(varvalue);
			if(command_timeout<1){
				syslog(LOG_ERR,"Invalid command_timeout specified in config file '%s' - Line %d\n",filename,line);
				return ERROR;
			        }
		        }

		else{
			syslog(LOG_ERR,"Unknown option specified in config file '%s' - Line %d\n",filename,line);

			return ERROR;
		        }

	        }


	/* close the config file */
	fclose(fp);

	return OK;
	}



/* adds a new command definition from the config file to the list in memory */
int add_command(char *command_name, char *command_line){
	command *new_command;

	/* allocate memory for the new command */
	new_command=(command *)malloc(sizeof(command));
	if(new_command==NULL)
		return ERROR;

	strcpy(new_command->command_name,command_name);
	strcpy(new_command->command_line,command_line);

	/* add new command to head of list in memory */
	new_command->next=command_list;
	command_list=new_command;

	if(debug==TRUE)
		syslog(LOG_DEBUG,"Added command[%s]=%s\n",command_name,command_line);

	return OK;
        }



/* given a command name, find the structure in memory */
command *find_command(char *command_name){
	command *temp_command;

	for(temp_command=command_list;temp_command!=NULL;temp_command=temp_command->next)
		if(!strcmp(command_name,temp_command->command_name))
			return temp_command;

	return NULL;
        }



/* wait for incoming connection requests */
void wait_for_connections(void){
	struct sockaddr_in myname;
	struct sockaddr_in *nptr;
	struct sockaddr addr;
	int rc;
	int sock, new_sd, addrlen;
	char connecting_host[16];
	pid_t pid;
	int flag=1;

	/* create a socket for listening */
	sock=socket(AF_INET,SOCK_STREAM,0);

	/* exit if we couldn't create the socket */
	if(sock<0){
	        syslog(LOG_ERR,"Network server socket failure (%d: %s)",errno,strerror(errno));
	        exit (STATE_CRITICAL);
		}

        /* set the reuse address flag so we don't get errors when restarting */
        flag=1;
        if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char *)&flag,sizeof(flag))<0){
		syslog(LOG_ERR,"Could not set reuse address option on socket!\n");
		exit(STATE_UNKNOWN);
	        }

	myname.sin_family=AF_INET;
	myname.sin_port=htons(server_port);
 	bzero(&myname.sin_zero,8);

	/* what address should we bind to? */
        if(!strlen(server_address))
		myname.sin_addr.s_addr=INADDR_ANY;

	else if(!my_inet_aton(server_address,&myname.sin_addr)){
		syslog(LOG_ERR,"Server address is not a valid IP address\n");
		exit (STATE_CRITICAL);
                }


	/* bind the address to the Internet socket */
	if(bind(sock,(struct sockaddr *)&myname,sizeof(myname))<0){
		syslog(LOG_ERR,"Network server bind failure (%d: %s)\n",errno,strerror(errno));
	        exit (STATE_CRITICAL);
	        }

	/* open the socket for listening */
	if(listen(sock,5)<0){
	    	syslog(LOG_ERR,"Network server listen failure (%d: %s)\n",errno,strerror(errno));
	        exit (STATE_CRITICAL);
		}

	/* log info to syslog facility */
        syslog(LOG_NOTICE,"Starting up daemon");

	/* Trap signals */
	signal(SIGQUIT,sighandler);
	signal(SIGTERM,sighandler);

	if(debug==TRUE){
		syslog(LOG_DEBUG,"Listening for connections on port %d\n",htons(myname.sin_port));
		syslog(LOG_DEBUG,"Allowing connections from: %s\n",allowed_hosts);
	        }

	/* listen for connection requests - fork() if we get one */
	while(1){

		/* wait for a connection request */
	        while(1){
			new_sd=accept(sock,0,0);
			if(new_sd>=0 || (errno!=EWOULDBLOCK && errno!=EINTR))
				break;
			sleep(1);
		        }

		/* hey, there was an error... */
		if(new_sd<0){

			/* log error to syslog facility */
			syslog(LOG_ERR,"Network server accept failure (%d: %s)",errno,strerror(errno));

			/* close socket prioer to exiting */
			close(sock);

			return;
			}

		/* child process should handle the connection */
    		pid=fork();
    		if(pid==0){

			/* fork again so we don't create zombies */
			pid=fork();
			if(pid==0){

				/* grandchild does not need to listen for connections, so close the socket */
				close(sock);  

				/* find out who just connected... */
				addrlen=sizeof(addr);
				rc=getpeername(new_sd,&addr,&addrlen);

				if(rc<0){

				        /* log error to syslog facility */
					syslog(LOG_ERR,"Error: Network server getpeername() failure (%d: %s)",errno,strerror(errno));

				        /* close socket prior to exiting */
					close(new_sd);

					return;
		                        }

				nptr=(struct sockaddr_in *)&addr;

				/* log info to syslog facility */
				if(debug==TRUE)
					syslog(LOG_DEBUG,"Connection from %s port %d",inet_ntoa(nptr->sin_addr),nptr->sin_port);

				/* is this is a blessed machine? */
				snprintf(connecting_host,sizeof(connecting_host),"%s",inet_ntoa(nptr->sin_addr));
				connecting_host[sizeof(connecting_host)-1]='\x0';

				if(!is_an_allowed_host(connecting_host)){

				        /* log error to syslog facility */
					syslog(LOG_ERR,"Host %s is not allowed to talk to us!",connecting_host);
			                }
				else{

				        /* log info to syslog facility */
					if(debug==TRUE)
						syslog(LOG_DEBUG,"Host address checks out ok");

				        /* handle the client connection */
					handle_connection(new_sd);
			                }

				/* log info to syslog facility */
				if(debug==TRUE)
					syslog(LOG_DEBUG,"Connection from %s closed.",connecting_host);

				/* close socket prior to exiting */
				close(new_sd);

				return;
    			        }

			/* first child returns immediately, grandchild is inherited by INIT process -> no zombies... */
			else
				exit(STATE_OK);
		        }
		
		/* parent ... */
		else{
			/* parent doesn't need the new connection */
			close(new_sd);

			/* parent waits for first child to exit */
			waitpid(pid,NULL,0);
		        }
  		}

	/* we shouldn't ever get here... */
	syslog(LOG_NOTICE,"Terminating");

	return;
	}



/* handles a client connection */
void handle_connection(int sock){
	command *temp_command;
	packet receive_packet;
	packet send_packet;
	int bytes_to_send;
	int bytes_to_recv;
	char buffer[MAX_INPUT_BUFFER];
	int result=STATE_OK;
	int early_timeout=FALSE;
	int rc;


	/* log info to syslog facility */
	if(debug==TRUE)
		syslog(LOG_DEBUG,"Handling the connection...");

	/* socket should be non-blocking */
	fcntl(sock,F_SETFL,O_NONBLOCK);

	bytes_to_recv=sizeof(receive_packet);
	rc=recvall(sock,(char *)&receive_packet,&bytes_to_recv,socket_timeout);

	/* recv() error or client disconnect */
	if(rc<=0){

		/* log error to syslog facility */
		syslog(LOG_ERR,"Could not read request from client, bailing out...");

		return;
                }

	/* we couldn't read the correct amount of data, so bail out */
	else if(bytes_to_recv!=sizeof(receive_packet)){

		/* log error to syslog facility */
		syslog(LOG_ERR,"Data packet from client was too short, bailing out...");

		return;
	        }

	/* make sure this is the right type of packet */
	if(ntohl(receive_packet.packet_type)!=QUERY_PACKET || ntohl(receive_packet.packet_version)!=NRPE_PACKET_VERSION_1){

		/* log error to syslog facility */
		syslog(LOG_ERR,"Received invalid packet from client, bailing out...");

		return;
	        }

	/* log info to syslog facility */
	if(debug==TRUE)
		syslog(LOG_DEBUG,"Host is asking for command '%s' to be run...",receive_packet.buffer);

	/* if this is the version check command, just spew it out */
	if(!strcmp(&receive_packet.buffer[0],NRPE_HELLO_COMMAND)){

		snprintf(buffer,sizeof(buffer),"NRPE v%s",PROGRAM_VERSION);
		buffer[sizeof(buffer)-1]='\x0';

		/* log info to syslog facility */
		if(debug==TRUE)
			syslog(LOG_DEBUG,"Response: %s",buffer);

		result=STATE_OK;
	        }

	/* find the command we're supposed to run */
	else{
		temp_command=find_command(receive_packet.buffer);
		if(temp_command==NULL){

			snprintf(buffer,sizeof(buffer),"NRPE: Command '%s' not defined",receive_packet.buffer);
			buffer[sizeof(buffer)-1]='\x0';

			/* log error to syslog facility */
			if(debug==TRUE)
				syslog(LOG_DEBUG,"%s",buffer);

			result=STATE_CRITICAL;
	                }

		else{

			/* log info to syslog facility */
			if(debug==TRUE)
				syslog(LOG_DEBUG,"Running command: %s",temp_command->command_line);

			/* run the command */
			strcpy(buffer,"");
			result=my_system(temp_command->command_line,command_timeout,&early_timeout,buffer,sizeof(buffer));

			/* see if the command timed out */
			if(early_timeout==TRUE)
				snprintf(buffer,sizeof(buffer)-1,"NRPE: Command timed out after %d seconds\n",command_timeout);
			else if(!strcmp(buffer,""))
				snprintf(buffer,sizeof(buffer)-1,"NRPE: Unable to read output\n");

			buffer[sizeof(buffer)-1]='\x0';

			/* check return code bounds */
			if((result<0) || (result>3)){

				/* log error to syslog facility */
				syslog(LOG_ERR,"Bad return code for [%s]: %d", buffer,result);

				result=STATE_UNKNOWN;
			        }
		        }
	        }

	/* strip newline character from end of output buffer */
	if(buffer[strlen(buffer)-1]=='\n')
		buffer[strlen(buffer)-1]='\x0';

	/* clear the response packet buffer */
	bzero(&send_packet,sizeof(send_packet));

	/* fill the response packet with data */
	send_packet.packet_type=htonl(RESPONSE_PACKET);
	send_packet.packet_version=htonl(NRPE_PACKET_VERSION_1);
	send_packet.result_code=htonl(result);
	send_packet.buffer_length=htonl(strlen(buffer));
	strncpy(&send_packet.buffer[0],buffer,sizeof(send_packet.buffer));
	send_packet.buffer[sizeof(send_packet.buffer)-1]='\x0';
	
	/* send the response back to the client */
	bytes_to_send=sizeof(send_packet);
	sendall(sock,(char *)&send_packet,&bytes_to_send);

	/* log info to syslog facility */
	if(debug==TRUE)
		syslog(LOG_DEBUG,"Return Code: %d, Output: %s",result,buffer);

	return;
        }



/* checks to see if a given host is allowed to talk to us */
int is_an_allowed_host(char *connecting_host){
	char temp_buffer[MAX_INPUT_BUFFER];
	char *temp_ptr;

	strncpy(temp_buffer,allowed_hosts,sizeof(temp_buffer));
	temp_buffer[sizeof(temp_buffer)-1]='\x0';

	for(temp_ptr=strtok(temp_buffer,",");temp_ptr!=NULL;temp_ptr=strtok(NULL,",")){
		if(!strcmp(connecting_host,temp_ptr))
			return 1;
	        }

	return 0;
        }



/* handle signals */
void sighandler(int sig){

	/* free all memory we allocated */
	free_memory();
	
	/* terminate... */
	exit(0);

	/* so the compiler doesn't complain.. */
	return;
        }



/* free all allocated memory */
void free_memory(void){
	command *this_command;
	command *next_command;
	
	/* free memory for the command list */
	this_command=command_list;
	while(this_command!=NULL){
		next_command=this_command->next;
		free(this_command);
		this_command=next_command;
	        }

	return;
        }




/* executes a system command via popen(), but protects against timeouts */
int my_system(char *command,int timeout,int *early_timeout,char *output,int output_length){
        pid_t pid;
	int status;
	int result;
	extern int errno;
	char buffer[MAX_INPUT_BUFFER];
	int fd[2];
	FILE *fp;
	int bytes_read=0;
	time_t start_time,end_time;

	/* initialize return variables */
	if(output!=NULL)
		strcpy(output,"");
	*early_timeout=FALSE;

	/* if no command was passed, return with no error */
	if(command==NULL)
	        return STATE_OK;

	/* create a pipe */
	pipe(fd);

	/* make the pipe non-blocking */
	fcntl(fd[0],F_SETFL,O_NONBLOCK);
	fcntl(fd[1],F_SETFL,O_NONBLOCK);

	/* get the command start time */
	time(&start_time);

	/* fork */
	pid=fork();

	/* return an error if we couldn't fork */
	if(pid==-1){

		snprintf(buffer,sizeof(buffer)-1,"NRPE: Call to fork() failed\n");
		buffer[sizeof(buffer)-1]='\x0';

		if(output!=NULL){
			strncpy(output,buffer,output_length-1);
			output[output_length-1]='\x0';
		        }

		/* close both ends of the pipe */
		close(fd[0]);
		close(fd[1]);
		
	        return STATE_UNKNOWN;  
	        }

	/* execute the command in the child process */
        if(pid==0){

		/* close pipe for reading */
		close(fd[0]);

		/* become process group leader */
		setpgid(0,0);

		/* trap commands that timeout */
		signal(SIGALRM,my_system_sighandler);
		alarm(timeout);

		/* run the command */
		fp=popen(command,"r");
		
		/* report an error if we couldn't run the command */
		if(fp==NULL){

			strncpy(buffer,"NRPE: Call to popen() failed\n",sizeof(buffer)-1);
			buffer[sizeof(buffer)-1]='\x0';

			/* write the error back to the parent process */
			write(fd[1],buffer,strlen(buffer)+1);

			result=STATE_CRITICAL;
		        }
		else{

			/* read in the first line of output from the command */
			fgets(buffer,sizeof(buffer)-1,fp);

			/* close the command and get termination status */
			status=pclose(fp);

			/* report an error if we couldn't close the command */
			if(status==-1)
				result=STATE_CRITICAL;
			else
				result=WEXITSTATUS(status);

			/* write the output back to the parent process */
			write(fd[1],buffer,strlen(buffer)+1);
		        }

		/* close pipe for writing */
		close(fd[1]);

		/* reset the alarm */
		alarm(0);

		exit(result);
	        }

	/* parent waits for child to finish executing command */
	else{
		
		/* close pipe for writing */
		close(fd[1]);

		/* wait for child to exit */
		waitpid(pid,&status,0);

		/* get the end time for running the command */
		time(&end_time);

		/* get the exit code returned from the program */
		result=WEXITSTATUS(status);

		/* because of my idiotic idea of having UNKNOWN states be equivalent to -1, I must hack things a bit... */
		if(result==255)
			result=STATE_UNKNOWN;

		/* check bounds on the return value */
		if(result<0 || result>3)
			result=STATE_UNKNOWN;

		/* try and read the results from the command output (retry if we encountered a signal) */
		if(output!=NULL){
			do{
				bytes_read=read(fd[0],output,output_length-1);
		                }while(bytes_read==-1 && errno==EINTR);
		        }

		if(bytes_read==-1 && output!=NULL)
			strcpy(output,"");

		/* if there was a critical return code and no output AND the command time exceeded the timeout thresholds, assume a timeout */
		if(result==STATE_CRITICAL && bytes_read==-1 && (end_time-start_time)>=timeout){
			*early_timeout=TRUE;

			/* send termination signal to child process group */
			kill((pid_t)(-pid),SIGTERM);
			kill((pid_t)(-pid),SIGKILL);
		        }

		/* close the pipe for reading */
		close(fd[0]);
	        }

#ifdef DEBUG
	printf("my_system() end\n");
#endif

	return result;
        }



/* handle timeouts when executing commands via my_system() */
void my_system_sighandler(int sig){

	/* force the child process to exit... */
	exit(STATE_CRITICAL);
        }



/* drops privileges */
int drop_privileges(char *user, char *group){
	uid_t uid=-1;
	gid_t gid=-1;
	struct group *grp;
	struct passwd *pw;

	/* set effective group ID */
	if(group!=NULL){
		
		/* see if this is a group name */
		if(strspn(group,"0123456789")<strlen(group)){
			grp=(struct group *)getgrnam(group);
			if(grp!=NULL)
				gid=(gid_t)(grp->gr_gid);
			else
				syslog(LOG_ERR,"Warning: Could not get group entry for '%s'",group);
		        }

		/* else we were passed the GID */
		else
			gid=(gid_t)atoi(group);

		/* set effective group ID if other than current EGID */
		if(gid!=getegid()){

			if(setgid(gid)==-1)
				syslog(LOG_ERR,"Warning: Could not set effective GID=%d",(int)gid);
		        }
	        }


	/* set effective user ID */
	if(user!=NULL){
		
		/* see if this is a user name */
		if(strspn(user,"0123456789")<strlen(user)){
			pw=(struct passwd *)getpwnam(user);
			if(pw!=NULL)
				uid=(uid_t)(pw->pw_uid);
			else
				syslog(LOG_ERR,"Warning: Could not get passwd entry for '%s'",user);
		        }

		/* else we were passed the UID */
		else
			uid=(uid_t)atoi(user);
			
#ifdef HAVE_INITGROUPS

		if(uid!=geteuid()){

			/* initialize supplementary groups */
			if(initgroups(user,gid)==-1){
				if(errno==EPERM)
					syslog(LOG_ERR,"Warning: Unable to change supplementary groups using initgroups()");
				else{
					syslog(LOG_ERR,"Warning: Possibly root user failed dropping privileges with initgroups()");
					return ERROR;
			                }
	                        }
		        }
#endif

		if(setuid(uid)==-1)
			syslog(LOG_ERR,"Warning: Could not set effective UID=%d",(int)uid);
	        }

	return OK;
        }


/* process command line arguments */
int process_arguments(int argc, char **argv){
	int x;


	/* no options were supplied */
	if(argc<2)
		return ERROR;

	/* process all arguments */
	for(x=2;x<=argc;x++){

		if(!strcmp(argv[x-1],"-c")){
			if(x<argc){
				strncpy(config_file,argv[x],sizeof(config_file)-1);
				config_file[sizeof(config_file)-1]='\x0';
				x++;
			        }
			else
				return ERROR;
		        }
		else if(!strcmp(argv[x-1],"-d") || !strcmp(argv[x-1],"--daemon"))
			use_inetd=FALSE;
		else if(!strcmp(argv[1],"-i") || !strcmp(argv[x-1],"--inetd"))
			use_inetd=TRUE;
		else if(!strcmp(argv[x-1],"-h") || !strcmp(argv[x-1],"--help"))
			show_help=TRUE;
		else if(!strcmp(argv[x-1],"-l") || !strcmp(argv[x-1],"--license"))
			show_license=TRUE;
		else if(!strcmp(argv[x-1],"-V") || !strcmp(argv[x-1],"--version"))
			show_version=TRUE;
		else
			return ERROR;
	        }

	return OK;
        }

