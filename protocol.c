/*
**	BPALogin v1.5 - lightweight portable BIDS2 login client
**	Copyright (c) 1999  Shane Hyde (shyde@trontech.com.au)
** 
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
** 
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
** 
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
*/ 

#include "bpalogin.h"

/* MD5 context. */
typedef struct {
    unsigned int state[4];		/* state (ABCD) */
    unsigned int count[2];		/* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];	/* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *, unsigned char *, unsigned int);
void MD5Final(unsigned char[16], MD5_CTX *);

void genmd5(char *p,int len,char *digest)
{
    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context, p, len);
    MD5Final(digest, &context);
}

/*
**  This functions makes the MD5 based data packet which is used to login,
**  logout and handle heartbeats
*/
void makecredentials(char * credentials,struct session *s,INT2 msg,INT4 extra)
{
	INT2 j = htons(msg);
	int i=0;
	char buffer[150];
	INT4 ts = htonl(extra);

	memcpy(buffer,s->nonce,16);
	i += 16;
	memcpy(buffer+i,s->password,strlen(s->password));
	i += strlen(s->password);
	memcpy(buffer+i,&(ts),sizeof(INT4));
	i += sizeof(INT4);
	memcpy(buffer+i,&j,sizeof(INT2));
	i += sizeof(INT2);

	genmd5(buffer,i,credentials);
}

/*
**  Login to the Authentication server
**
**  Returns - 0 - failed to login for some reason.
**            1 - Logged in successfully
*/
int login(struct session * s)
{
	int err;
	char credentials[16];
	time_t logintime;

	int authsocket;
	struct transaction t;
	INT2 transactiontype;

	authsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	err = connect(authsocket,(struct sockaddr *)&s->authhost,sizeof(struct sockaddr_in));

	if(err)
	{
		s->noncritical("Cant connect to auth server");
		closesocket(authsocket);
		return 0;
	}

	/*
	** start the negotiation 
	*/
	start_transaction(&t,T_MSG_PROTOCOL_NEG_REQ,s->sessionid);
	add_field_INT2(s,&t,T_PARAM_CLIENT_VERSION,LOGIN_VERSION * 100);
	add_field_string(s,&t,T_PARAM_OS_IDENTITY,s->osname);
	add_field_string(s,&t,T_PARAM_OS_VERSION,s->osrelease);
	add_field_INT2(s,&t,T_PARAM_PROTOCOL_LIST,T_PROTOCOL_CHAL);

	send_transaction(s,authsocket,&t);

	transactiontype = receive_transaction(s,authsocket,&t);
	if(transactiontype != T_MSG_PROTOCOL_NEG_RESP)
	{
		s->critical("Logic error");
	}

	extract_valueINT2(s,&t,T_PARAM_STATUS_CODE,&s->retcode);
	extract_valuestring(s,&t,T_PARAM_LOGIN_SERVER_HOST,s->loginserverhost);
	extract_valueINT2(s,&t,T_PARAM_PROTOCOL_SELECT,&s->protocol);

	if(s->protocol != T_PROTOCOL_CHAL)
	{
		s->critical("Unsupported protocol");
	}

	switch(s->retcode)
	{
	case T_STATUS_SUCCESS:
	case T_STATUS_LOGIN_SUCCESS_SWVER:
		break;
	case T_STATUS_LOGIN_FAIL_SWVER:
		s->critical("Login failure: software version");
	case T_STATUS_LOGIN_FAIL_INV_PROT:
		s->critical("Login failure: invalid protocol");
	case T_STATUS_LOGIN_UNKNOWN:
		s->critical("Login failure: unknown");
	}

	closesocket(authsocket);

	authsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	err = connect(authsocket,(struct sockaddr *)&s->authhost,sizeof(struct sockaddr_in));

	start_transaction(&t,T_MSG_LOGIN_REQ,s->sessionid);
	add_field_string(s,&t,T_PARAM_USERNAME,s->username);
	add_field_INT2(s,&t,T_PARAM_CLIENT_VERSION,LOGIN_VERSION * 100);
	add_field_string(s,&t,T_PARAM_OS_IDENTITY,s->osname);
	add_field_string(s,&t,T_PARAM_OS_VERSION,s->osrelease);
	add_field_INT2(s,&t,T_PARAM_REASON_CODE,T_LOGIN_REASON_CODE_NORMAL);
	add_field_INT2(s,&t,T_PARAM_REQ_PORT,s->listenport);

	send_transaction(s,authsocket,&t);

	transactiontype = receive_transaction(s,authsocket,&t);
	if(transactiontype == T_MSG_LOGIN_RESP)
		goto skippo;

	if(transactiontype != T_MSG_AUTH_RESP)
	{
		s->critical("logic error");
	}

	if(!extract_valueINT2(s,&t,T_PARAM_HASH_METHOD,&s->hashmethod))
	{
		s->critical("AUTH: no hashmethod");
	}
	if(!extract_valuestring(s,&t,T_PARAM_NONCE,s->nonce))
	{
		s->critical("Auth: no nonce");
	}

	if(s->hashmethod == T_AUTH_MD5_HASH)
	{
		genmd5(s->password,strlen(s->password),s->password);
	}

	start_transaction(&t,T_MSG_LOGIN_AUTH_REQ,s->sessionid);

	s->timestamp = time(NULL);
	makecredentials(credentials,s,T_MSG_LOGIN_AUTH_REQ,s->timestamp);

	add_field_data(s,&t,T_PARAM_AUTH_CREDENTIALS,credentials,16);
	add_field_INT4(s,&t,T_PARAM_TIMESTAMP,s->timestamp);

	send_transaction(s,authsocket,&t);

	transactiontype = receive_transaction(s,authsocket,&t);
skippo:
	if(transactiontype != T_MSG_LOGIN_RESP)
	{
		s->critical("logic error");
	}

	extract_valueINT2(s,&t,T_PARAM_STATUS_CODE,&s->retcode);
	switch(s->retcode)
	{
	case T_STATUS_SUCCESS:
	case T_STATUS_LOGIN_SUCCESSFUL_SWVER:
	case T_STATUS_LOGIN_SUCCESSFUL_ALREADY_LOGGED_IN:
		break;
	case T_STATUS_USERNAME_NOT_FOUND:
		s->critical("Login failure: username not known");
	case T_STATUS_INCORRECT_PASSWORD:
		s->critical("Login failure: incorrect password");
	case T_STATUS_ACCOUNT_DISABLED:
		s->critical("Login failure: disabled");
	case T_STATUS_LOGIN_RETRY_LIMIT:
	case T_STATUS_USER_DISABLED:
	case T_STATUS_FAIL_USERNAME_VALIDATE:
	case T_STATUS_FAIL_PASSWORD_VALIDATE:
	case T_STATUS_LOGIN_UNKNOWN:
		s->critical("Login failure: other error");
	}

	extract_valueINT2(s,&t,T_PARAM_LOGOUT_SERVICE_PORT,&s->logoutport);
	extract_valueINT2(s,&t,T_PARAM_STATUS_SERVICE_PORT,&s->statusport);
	extract_valuestring(s,&t,T_PARAM_TSMLIST,s->tsmlist);
	extract_valuestring(s,&t,T_PARAM_RESPONSE_TEXT,s->resptext);

	logintime = time(NULL);

	s->debug(0,"Logged on as %s - successful at %s",s->username,asctime(localtime(&logintime)));
	s->sequence = 0;

	closesocket(authsocket);
	return 1;
}

/*
**  Handle heartbeats, wait for the following events to happen -
**    
**    1. A heartbeat packet arrives, in which case we reply correctly
**    2. A timeout occured (ie no heartbeat arrived within 7 minutes)
**    3. The socket was closed.
**
**  Returns - 0 - Heartbeat timeout, and subsequent login failed to connect
**            1 - Socket closed on us, presuming the user wants to shut down.
*/
int handle_heartbeats(struct session *s)
{
	INT2 transactiontype;
	struct transaction t;

	while(1)
	{
		transactiontype = receive_udp_transaction(s,s->listensock,&t,&s->fromaddr);
		if(transactiontype == 0xffff)
		{
			s->debug(0,"Timed out waiting for heartbeat - logging on\n");
			s->ondisconnected();
			if(!login(s))
				return 0;
			s->onconnected(s->listenport);
		}
		else if(transactiontype == 0xfffe)
		{
			s->debug(0,"Socket closed - shutting down\n");
			return 1;
		}
		else if(transactiontype == T_MSG_STATUS_REQ)
		{
			char buf[16];

			start_transaction(&t,T_MSG_STATUS_RESP,s->sessionid);
			add_field_INT2(s,&t,T_PARAM_STATUS_CODE,T_STATUS_TRANSACTION_OK);

			s->sequence++;
			makecredentials(buf,s,T_MSG_STATUS_RESP,s->sequence);
			add_field_data(s,&t,T_PARAM_STATUS_AUTH,buf,16);
			add_field_INT4(s,&t,T_PARAM_SEQNUM,s->sequence);

			send_udp_transaction(s,&t);

			s->lastheartbeat = time(NULL);

			s->debug(1,"Responded to heartbeat at %s",asctime(localtime(&s->lastheartbeat)));
		}
		else if(transactiontype == T_MSG_RESTART_REQ)
		{
			s->critical("Restart request - unimplemented");
		}
		else
		{
			/*
			**  Melbourne servers were sending spurious UDP packets after authentication
			**  This works around it.
			*/
			s->debug(0,"Unknown heartbeat message %d ",transactiontype);
		}
	}
	/*
	**  Should never get here
	*/
	return 0;
}

/*
**  Logout of the BIDS2 system
**    
**  Returns - 0 - Could not connect to logout.
**            1 - Logout successful.
*/
int logout(INT2 reason,struct session * s)
{
	int err;
	char credentials[16];
	time_t logintime;

	int authsocket;
	struct transaction t;
	INT2 transactiontype;

	authsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	err = connect(authsocket,(struct sockaddr *)&s->authhost,sizeof(struct sockaddr_in));

	if(err)
	{
		s->noncritical("Cant connect to auth server");
		closesocket(authsocket);
		return 0;
	}

	/*
	** start the negotiation 
	*/
	start_transaction(&t,T_MSG_LOGOUT_REQ,s->sessionid);
	add_field_string(s,&t,T_PARAM_USERNAME,s->username);
	add_field_INT2(s,&t,T_PARAM_CLIENT_VERSION,LOGIN_VERSION * 100);
	add_field_string(s,&t,T_PARAM_OS_IDENTITY,s->osname);
	add_field_string(s,&t,T_PARAM_OS_VERSION,s->osrelease);
	add_field_INT2(s,&t,T_PARAM_REASON_CODE,reason);

	send_transaction(s,authsocket,&t);

	transactiontype = receive_transaction(s,authsocket,&t);
	if(transactiontype != T_MSG_AUTH_RESP)
	{
		s->critical("logic error");
	}

	if(!extract_valueINT2(s,&t,T_PARAM_HASH_METHOD,&s->hashmethod))
	{
		s->critical("AUTH: no hashmethod");
	}
	if(!extract_valuestring(s,&t,T_PARAM_NONCE,s->nonce))
	{
		s->critical("Auth: no nonce");
	}

	if(s->hashmethod == T_AUTH_MD5_HASH)
	{
		genmd5(s->password,strlen(s->password),s->password);
	}

	start_transaction(&t,T_MSG_LOGOUT_AUTH_RESP,s->sessionid);

	s->timestamp = time(NULL);
	makecredentials(credentials,s,T_MSG_LOGOUT_AUTH_RESP,s->timestamp);

	add_field_data(s,&t,T_PARAM_AUTH_CREDENTIALS,credentials,16);
	add_field_INT4(s,&t,T_PARAM_TIMESTAMP,s->timestamp);

	send_transaction(s,authsocket,&t);

	transactiontype = receive_transaction(s,authsocket,&t);
	if(transactiontype != T_MSG_LOGOUT_RESP)
	{
		s->critical("logic error");
	}

	extract_valueINT2(s,&t,T_PARAM_STATUS_CODE,&s->retcode);
	switch(s->retcode)
	{
	case T_STATUS_SUCCESS:
	case T_STATUS_LOGOUT_SUCCESSFUL_ALREADY_DISCONNECTED:
		break;
	case T_STATUS_USERNAME_NOT_FOUND:
		s->critical("Login failure: username not known");
	case T_STATUS_INCORRECT_PASSWORD:
		s->critical("Login failure: incorrect password");
	case T_STATUS_ACCOUNT_DISABLED:
		s->critical("Login failure: disabled");
	case T_STATUS_LOGIN_RETRY_LIMIT:
	case T_STATUS_USER_DISABLED:
	case T_STATUS_FAIL_USERNAME_VALIDATE:
	case T_STATUS_FAIL_PASSWORD_VALIDATE:
	case T_STATUS_LOGIN_UNKNOWN:
		s->critical("Login failure: other error");
	}

	extract_valueINT2(s,&t,T_PARAM_LOGOUT_SERVICE_PORT,&s->logoutport);
	extract_valueINT2(s,&t,T_PARAM_STATUS_SERVICE_PORT,&s->statusport);
	extract_valuestring(s,&t,T_PARAM_TSMLIST,s->tsmlist);
	extract_valuestring(s,&t,T_PARAM_RESPONSE_TEXT,s->resptext);

	logintime = time(NULL);

	s->debug(0,"Logged out successful at %s",asctime(localtime(&logintime)));
	
	closesocket(authsocket);
	
	return 1;
}
