/************************************************************************************************
 *
 * NETUTILS.H - NRPE Network Utilities Include File
 *
 * License: GPL
 * Copyright (c) 1999-2002 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 02-21-2002
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

int my_tcp_connect(char *,int,int *);
int my_connect(char *,int,int *,char *);

int my_inet_aton(register const char *,struct in_addr *);

void strip(char *);

int sendall(int,char *,int *);
int recvall(int,char *,int *,int);





