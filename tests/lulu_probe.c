/* Account-free network probe; never reads Claude files. */
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
int main(int argc,char **argv){
 if(argc!=4)return 64;
 if(!strcmp(argv[1],"ssh")){
  execl("/usr/bin/ssh","ssh","-F","/dev/null","-o","BatchMode=yes","-o","IdentityAgent=none","-o","IdentitiesOnly=yes","-o","IdentityFile=/dev/null","-o","UserKnownHostsFile=/dev/null","-o","StrictHostKeyChecking=no","-o","ConnectTimeout=2","-p",argv[3],argv[2],NULL);return 98;
 }
 if(!strcmp(argv[1],"child")){pid_t p=fork();if(p==0){execl(argv[0],argv[0],"tcp",argv[2],argv[3],NULL);_exit(98);}int s;waitpid(p,&s,0);return WIFEXITED(s)?WEXITSTATUS(s):99;}
 int dns=!strcmp(argv[1],"dns");int udp=dns||!strcmp(argv[1],"udp");int af=strchr(argv[2],':')?AF_INET6:AF_INET;
 unsigned char query[]={0x47,0x55,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
 const void *payload=dns?(void*)query:(void*)"guard-fixture";size_t length=dns?sizeof(query):13;
 int s=socket(af,udp?SOCK_DGRAM:SOCK_STREAM,0);if(s<0)return 65;
 struct timeval timeout={3,0};setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
 int r=-1;
 if(af==AF_INET){struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(atoi(argv[3]));if(inet_pton(AF_INET,argv[2],&a.sin_addr)!=1)return 66;r=udp?sendto(s,payload,length,0,(void*)&a,sizeof(a)):connect(s,(void*)&a,sizeof(a));}
 else{struct sockaddr_in6 a={0};a.sin6_family=AF_INET6;a.sin6_port=htons(atoi(argv[3]));if(inet_pton(AF_INET6,argv[2],&a.sin6_addr)!=1)return 66;r=udp?sendto(s,payload,length,0,(void*)&a,sizeof(a)):connect(s,(void*)&a,sizeof(a));}
 if(dns&&r>=0){unsigned char reply[1024];r=recv(s,reply,sizeof(reply),0);if(r<12||reply[0]!=0x47||reply[1]!=0x55)r=-1;}
 if(r<0)fprintf(stderr,"probe denied or unavailable: %d\n",errno);close(s);return r>=0?0:13;
}
