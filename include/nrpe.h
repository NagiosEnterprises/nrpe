/****************************************************************************
 *
 * nrpe.h - Nagios Remote Plugin Executor header file
 *
 * License: GPLv2
 * Copyright (c) 2006-2017 Nagios Enterprises
 *               1999-2006 Ethan Galstad (nagios@nagios.org)
 *
 * License Notice:
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************************/

typedef struct command_struct {
	char					*command_name;
	char					*command_line;
	struct command_struct	*next;
} command;

int init(void);
void init_ssl(void);
void log_ssl_startup(void);
void usage(int);
void run_inetd(void);
void run_src(void);
void run_daemon(void);
void set_stdio_sigs(void);
void cleanup(void);
int read_config_file(char *);
int read_config_dir(char *);
int get_log_facility(char *);
int add_command(char *,char *);
command *find_command(char *);
void create_listener(struct addrinfo *ai);
void wait_for_connections(void);
void setup_wait_conn(void);
int wait_conn_fork(int sock);
void conn_check_peer(int sock);
void handle_connection(int);
void init_handle_conn(void);
int handle_conn_ssl(int sock, void *ssl_ptr);
int read_packet(int sock, void *ssl_ptr, v2_packet *v2_pkt, v3_packet **v3_pkt);
void free_memory(void);
int my_system(char*, int, int*, char**);	/* executes a command via popen(), but also protects against timeouts */
void my_system_sighandler(int);				/* handles timeouts when executing commands via my_system() */
void my_connection_sighandler(int);			/* handles timeouts of connection */
int drop_privileges(char *,char *, int);
int write_pid_file(void);
int remove_pid_file(void);
int check_privileges(void);
void sighandler(int);
void child_sighandler(int);
int validate_request(v2_packet *, v3_packet *);
int contains_nasty_metachars(char *);
int process_macros(char *,char *,int);
int process_arguments(int,char **);
