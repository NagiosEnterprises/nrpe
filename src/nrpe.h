/************************************************************************
 *
 * NRPE.H - NRPE Include File
 * Copyright (c) 1999-2002 Ethan Galstad (nagios@nagios.org)
 * Last Modified: 02-21-2002
 *
 * License:
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
 ************************************************************************/


/**************** COMMAND STRUCTURE DEFINITION **********/

#define MAX_COMMANDNAME_LENGTH	32		/* maximum short name of a command */
#define MAX_COMMANDLINE_LENGTH	1024		/* maximum command line length */

typedef struct command_struct{
	char command_name[MAX_COMMANDNAME_LENGTH];
	char command_line[MAX_COMMANDLINE_LENGTH];
	struct command_struct *next;
        }command;

