/*
*       userdbmanager is a simple tool to add/delete user with password for libpam-userdb authentication
*       author Eric Weiss < e r i c . w e i s s @p r e v a s . d k >
*       
*
*/
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <db.h>
#include <termios.h>

#define DATABASE        "/var/dbng/pam.db"
#define PWLEN 34 // max password lenght +2
enum OPTCMD {ADDUSER,CHPW,DELUSER,RMDB,DUMP,USEREXISTS,HELP} ;
typedef enum pwt {CLEARTEXT,CRYPTED} pwtype ;
char * database=DATABASE;

int  help(){
	printf(" -a username : Add User -p password is required\n");
	printf(" -d username : Del User\n");
	printf(" -u username : Update user's passwd -p password is required \n");
	printf(" -p passwd : use this as password ( unsecure !! )\n");
	printf(" -r  : remove Database\n");
        printf(" -e username : Check if user exists\n");
	printf(" -f filemame  : set databe to filename default /tmp/pam.db\n");
	printf(" -D  : Dump\n");
	return 0;
}


int  get_password(char *password)
{       
        int res=0;
        printf("Please enter password:");
        static struct termios old_terminal;
        static struct termios new_terminal;
        tcgetattr(STDIN_FILENO, &old_terminal);
        new_terminal = old_terminal;
        new_terminal.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);
        if (fgets(password, PWLEN, stdin) == NULL){
                password[0] = '\0';
        }else{
                if (!strchr(password, '\n')) {
                        res=-1;
                }else{
                        password[strlen(password)-1] = '\0';    
                }
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
        printf("\n");
        return res;
}
char * readpw()
{
        char password[128], c;
        int index = 0;
  
        printf("Enter Password : ");
        
        while((c = getchar()) != '\n'){
                if(index < 0){
                   index = 0;
                }
                if(c == 8){
                putchar('\b');
                putchar(0);
                putchar('\b');
                index--;
                continue;
                }
                password[index++] = c;
                putchar('*');
        }
        password[index] = '\0';
        return strdup(password);
}

DB *  getdb()
{
        DB * db;
        int ret;
        DBC *dbcp;
        
        if (db_create(&db, NULL, 0) != 0) {
                fprintf(stderr, "Error on db_create\n");
                return NULL;
        }
        if (db->set_pagesize(db, 1024) != 0) {
                fprintf(stderr, "Error on set_pagesize\n");
                (void)db->close(db, 0);
                 return NULL;
        }
        if (db->set_cachesize(db, 0, 32 * 1024, 0) != 0) {
                fprintf(stderr, "Error on set_cachesize\n");
                (void)db->close(db, 0);
                 return NULL;
        }
        if ( db->open(db,NULL, database, NULL, DB_HASH, DB_CREATE, 0664) != 0) {
                fprintf(stderr, "Error on opendb\n");
                (void)db->close(db, 0);
                return NULL;
        }
        return db;
}

int dumpuser  ( )
{
	DB *dbp;
        DBC *dbcp;
        DBT key, data;
        int res,ret;
        char * user="";
        dbp=getdb();
        if (dbp != NULL)
        {
                if ((ret = dbp->cursor(dbp, NULL, &dbcp, 0)) == 0) {
                        memset(&key, 0, sizeof(DBT));
                        memset(&data, 0, sizeof(DBT));
                        key.data = user;
                        key.size = (u_int32_t)strlen(user) ;
                        while ((ret = dbcp->get(dbcp, &key, &data, DB_NEXT)) == 0)
                        {
                                printf("%.*s : %.*s\n",(int)key.size, (char *)key.data,(int)data.size, (char *)data.data);
                        }
                        if (dbcp != NULL)
                        dbcp->close(dbcp);
                }
                else
                {
                        if (dbp != NULL)
                        dbp->close(dbp, 0);
                }
        }
}

int deluser ( char * user )
{
	DB *dbp;
        DBC *dbcp;
        DBT key;
        int res,ret;
        dbp=getdb();
        if (dbp != NULL)
        {
                if ((ret = dbp->cursor(dbp, NULL, &dbcp, 0)) == 0) {
                        memset(&key, 0, sizeof(DBT));
                        key.data = user;
                        key.size = (u_int32_t)strlen(user) ;
                        ret=dbp->del(dbp,NULL,&key,0);
                        if (ret == 0){
                                printf("Deleted %s \n",user);
                        }else{
                                printf("User %s does not exits\n",user);
                        }
                        dbcp->close(dbcp);
                }
                dbp->close(dbp, 0);
        }else{
                return 1;
        }
}

/* check is user exists */

int checkuser ( char * user  )
{
	DB *dbp;
        DBC *dbcp;
        DBT key,data;
        int res,ret;
        dbp=getdb();
        if (dbp != NULL)
        {
                if ((ret = dbp->cursor(dbp, NULL, &dbcp, 0)) == 0) {
                        memset(&key, 0, sizeof(DBT));
                        memset(&data, 0, sizeof(DBT));
                        key.data = user;
                        key.size = (u_int32_t)strlen(user) ;
                        ret=dbp->get(dbp,NULL,&key,&data,0);
                        if (ret == 0)
                        {
                                printf ( "User exists \n");
                        }else{
                                printf ( "User doesn't exists \n");
                        }
                        dbcp->close(dbcp);
                }
                dbp->close(dbp, 0);
        }else{
                ret=-1;
        }
        return ret;
}


/* change password for user */

int chpw ( char * user, char * pw , pwtype crypted  )
{
	
        DB *dbp;
        DBC *dbcp;
        DBT key,data;
        int res,ret;
        size_t len;
        char *salt = "$6$pt4wu5ns";
        dbp=getdb();
        if (dbp != NULL)
        {
                if ((ret = dbp->cursor(dbp, NULL, &dbcp, 0)) == 0) {
                        len = strlen(user);
                        memset(&key, 0, sizeof(DBT));
                        memset(&data, 0, sizeof(DBT));
                        key.data = user;
                        key.size = (u_int32_t)strlen(user) ;
                        ret=dbp->get(dbp,NULL,&key,&data,0);
                        if (ret == 0)
                        {
                                if ( crypted == CRYPTED )
                                {
                                        data.data=crypt(pw,salt);
                                        data.size=strlen(data.data);
                                }else{
                                        data.data=pw;
                                        data.size=strlen(pw);
                                }
                                ret=dbp->put(dbp,NULL,&key,&data,0);
                        }else{
                                printf ( "User doesn't exists \n");
                        }
                        dbcp->close(dbcp);
                }
                dbp->close(dbp, 0);
        }else{
                ret=-1;
        }
        return ret;
}

int adduser(char * user,char * pw, pwtype crypted)
{

        DB *dbp;
        DBC *dbcp;
        DBT key,data;
        int res,ret;
        size_t len;
        char *salt = "$6$pt4wu5ns";
        dbp=getdb();
        if (dbp != NULL)
        {
                if ((ret = dbp->cursor(dbp, NULL, &dbcp, 0)) == 0) {
                        len = strlen(user);
                        memset(&key, 0, sizeof(DBT));
                        memset(&data, 0, sizeof(DBT));
                        key.data = user;
                        key.size = (u_int32_t)strlen(user) ;
                        ret=dbp->get(dbp,NULL,&key,&data,0);
                        if (ret == 0)
                        {
                                printf ( "User does exists \n");
                        }else{
                                if ( crypted == CRYPTED )
                                {
                                        data.data=crypt(pw,salt);
                                        data.size=strlen(data.data);
                                }else{
                                        data.data=pw;
                                        data.size=strlen(pw);
                                }
                                ret=dbp->put(dbp,NULL,&key,&data,0);
                        }
                        dbcp->close(dbcp);
                }
                dbp->close(dbp, 0);
        }else{
                ret=-1;
        }
        return ret;
}

int main(int argc,char **argv)
{       enum OPTCMD task=HELP;
        extern int optind;
        size_t len;
        int ch,  rflag;
        int ret = EXIT_SUCCESS;
        char password[PWLEN],  *p, *t, buf[1024], rbuf[1024];
 	char *username = NULL;
	char *passwd = NULL;
        pwtype passwordtype =CLEARTEXT;
        while ((ch = getopt(argc, argv, "rca:e:d:u:p:f:hD")) != EOF)
        {
                switch (ch) {
                case 'r':
                        rflag = 1;
                break;
                case 'c':
                        passwordtype=CRYPTED;
                break;
		case 'f':
       			database = optarg;
       		break;		
		case 'a':
		        task=ADDUSER;
                        username = optarg;
        	break;		
		case 'e':
		        task=USEREXISTS;
                        username = optarg;
        	break;		
		case 'u':
		        task=CHPW;
     			username = optarg;
       		break;		
		case 'd':
		        task=DELUSER;
     			username = optarg;
       		break;		
		case 'D':
		        task=DUMP;
       		break;		
		case 'p':
       			passwd = optarg;
       		break;		
                case 'h':
		        return help();
                default:
                        help();
                }
        }
        argc -= optind;
        argv += optind;
        if (database == NULL)
        {
                database="/var/dbng/pam.db";
        }
        switch (task) {
                case  ADDUSER :
                if ((passwd != NULL) && (username != NULL)) {
                        adduser(username,passwd,passwordtype);
                }else
                {       
                        if (get_password(password)==0){
                                adduser(username,password,passwordtype);
                        }else{
                                printf("Password should no exeed %i characters\n",(PWLEN-2));
                        }
                        
                }
                break;
                case  DELUSER :
                        deluser(username);
                break;
                case  USEREXISTS :
                        ret=checkuser(username);
                break;
                case  DUMP :
                        dumpuser();
                break;
                case  CHPW :
                if (( passwd != NULL) && (username != NULL )) {
                        chpw(username,passwd,passwordtype);
                }else
                {
                        if (get_password(password)==0){
                                chpw(username,password,passwordtype);
                        }else{
                                printf("Password should no exeed %i characters\n",(PWLEN-2));
                        }
                }
                break;              
                case  RMDB :
                        remove(database);
                break;
                default:
                        help();

        }
        return ret;
}

