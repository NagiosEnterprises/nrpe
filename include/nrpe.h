/************************************************************************
 *
 * NRPE.H - NRPE Include File
 * Copyright (c) 1999-2003 Ethan Galstad (nagios@nagios.org)
 * Last Modified: 10-09-2003
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

typedef struct command_struct{
	char *command_name;
	char *command_line;
	struct command_struct *next;
        }command;

