/************************************************************************************************
 *
 * NETUTILS.H - NRPE Network Function Header File
 * Copyright (c) 1999-2001 Ethan Galstad (nagios@nagios.org)
 * Last Modified: 06-23-2001
 *
 * Description:
 *
 * This file contains common include files and function definitions used in many of the plugins.
 *
 * License Information:
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
 ************************************************************************************************/

#include "../common/config.h"

void socket_timeout_alarm_handler(int);

int process_tcp_request(char *address,int port,char *sbuffer,char *rbuffer,int rsize);
int process_udp_request(char *address,int port,char *sbuffer,char *rbuffer,int rsize);
int process_request(char *address,int port,char *proto,char *sbuffer,char *rbuffer,int rsize);

int my_tcp_connect(char *address,int port,int *sd);
int my_udp_connect(char *address,int port,int *sd);
int my_connect(char *address,int port,int *sd,char *proto);

int my_inet_aton(register const char *cp, struct in_addr *addr);

void strip(char *);





