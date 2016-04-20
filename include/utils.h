/************************************************************************************************
 *
 * UTILS.H - NRPE Utilities Include File
 *
 * License: GPL
 * Copyright (c) 1999-2006 Ethan Galstad (nagios@nagios.org)
 *
 * Last Modified: 12-11-2006
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

#ifndef NRPE_UTILS_H_INCLUDED
#define NRPE_UTILS_H_INCLUDED

#include "../include/config.h"

void generate_crc32_table(void);
unsigned long calculate_crc32(char*, int);
void randomize_buffer(char*,int);
int my_tcp_connect(char*, int, int*);
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE
int my_connect(const char*, struct sockaddr_storage*, u_short, int, const char*);
#else
int my_connect(const char*, struct sockaddr*, u_short, int, const char*);
#endif
void add_listen_addr(struct addrinfo**, int, char*, int);
int clean_environ(const char *keep_env_vars, const char *nrpe_user);
char* strip(char*);
int sendall(int, char*, int*);
int recvall(int, char*, int*, int);
char *my_strsep(char**, const char*);
int b64_decode(unsigned char *encoded);
void display_license(void);

#endif
