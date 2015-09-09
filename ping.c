#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>


#define NUM 5
#define UINT unsigned int
#define USHORT unsigned short
#define UCHAR unsigned char
#define ICMP_SIZE (sizeof(struct  icmp))
#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define BUF_SIZE 1024


struct icmp{
    UCHAR           type;      // 类型
    UCHAR           code;      // 代码
    USHORT          checksum;  // 校验和
    USHORT          id;        // 标识符
    USHORT          sequence;  // 序号 
    struct timeval  timestamp; // 时间戳
};


struct ip{
    // 主机字节序判断
    UCHAR   hlen:4;        // 首部长度
    UCHAR   version:4;     // 版本      
    UCHAR   tos;             // 服务类型
    USHORT  len;             // 总长度
    USHORT  id;                // 标识符
    USHORT  offset;            // 标志和片偏移
    UCHAR   ttl;            // 生存时间
    UCHAR   protocol;       // 协议
    USHORT  checksum;       // 校验和
    struct in_addr ipsrc;    // 32位源ip地址
    struct in_addr ipdst;   // 32位目的ip地址
};

char buf[BUF_SIZE]={0};

float timediff(struct  timeval *begin,struct  timeval *end);
USHORT checkSum(USHORT *, int); // 计算校验和
void pack(struct icmp *, int);  // 封装一个ICMP报文
int unpack(char *, int, char *);        // 对接收到的IP报文进行解包

int main(int argc, char const *argv[])
{
	if(argc < 2){
		printf("use: %s hostname/ip addr\n",argv[0]);
		exit(1);
	}

	int sockfd;
	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
		perror("socket() error");
		exit(1);
	}

	struct sockaddr_in from;
	struct sockaddr_in to;
	memset(&from,0,sizeof(struct  sockaddr_in));
	memset(&to,0,sizeof(struct  sockaddr_in));	

	to.sin_family=AF_INET;

	in_addr_t inaddr;
	struct  hostent *host;
	if(inaddr = inet_addr(argv[1]) == INADDR_NONE){
		if((host = gethostbyname(argv[1])) == NULL){
			perror("gethostbyname() error");
			exit(1);
		}
		to.sin_addr=*(struct in_addr *)host->h_addr_list[0];
	}else{
		to.sin_addr.s_addr=inaddr;
	}

	printf("PING %s(%s) %d bytes of data\n",argv[1],inet_ntoa(to.sin_addr),ICMP_SIZE);

	int nsend=0;
	int nreceived=0;
	socklen_t fromlen=sizeof(struct sockaddr_in);
	struct icmp sendicmp;
	for(int i=0;i<NUM;i++){
		nsend++;
		memset(&sendicmp,0,ICMP_SIZE);
		pack(&sendicmp,nsend);
		if(sendto(sockfd,&sendicmp,ICMP_SIZE,0,(struct sockaddr *)&to,sizeof(to)) == -1){
			printf("sendto() error\n");
			perror(strerror(errno));
			continue;
		}
		int n;
		if((n=recvfrom(sockfd,buf,BUF_SIZE,0,(struct sockaddr *)&from,&fromlen)) == -1){
			perror("recvfrom() error");
			continue;
		}
		sleep(1);
		nreceived++;
		if(unpack(buf,n,inet_ntoa(from.sin_addr)) == -1){
			perror("unpack() error");
		}
	}
	printf("---  %s ping statistics ---\n", argv[1]);
	printf("%d packets transmitted, %d received, %%%d packet loss\n", nsend,nreceived,(nsend-nreceived)/nsend*100);

	return 0;
}


USHORT checkSum(USHORT *addr, int len){
    UINT sum = 0;  
    while(len > 1){
        sum += *addr++;
        len -= 2;
    }

    // 处理剩下的一个字节
    if(len == 1){
        sum += *(UCHAR *)addr;
    }

    // 将32位的高16位与低16位相加
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (USHORT) ~sum;
}

float timediff(struct timeval *begin, struct timeval *end){
    int n;
    // 先计算两个时间点相差多少微秒
    n = ( end->tv_sec - begin->tv_sec ) * 1000000
        + ( end->tv_usec - begin->tv_usec );

    // 转化为毫秒返回
    return (float) (n / 1000);
}

void pack(struct icmp * icmp, int sequence){
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->id = getpid();
    icmp->sequence = sequence;
    gettimeofday(&icmp->timestamp, 0);
    icmp->checksum = checkSum((USHORT *)icmp, ICMP_SIZE);
}

int unpack(char * buf, int len, char * addr){
	struct ip *ip=(struct ip *)buf;
	int ipheadlen=ip->hlen <<2;
	struct icmp *icmp=(struct icmp *)(buf+ipheadlen);

	len-=ipheadlen;
   // 如果小于ICMP报文首部长度8
   if(len < 8){
        printf("ICMP packets\'s length is less than 8 \n"); 
        return -1;
   }
   if(icmp->type != ICMP_ECHOREPLY || icmp->id != getpid()){
   		printf("ICMP packets not send by us\n");
   		return -1;
   }

   struct timeval end;
   gettimeofday(&end,0);
   float rtt=timediff(&icmp->timestamp,&end);
   printf("%d bytes recvfrom %s:icmp_seq=%u ttl=%d rtt=%fms\n",len,addr,icmp->sequence,ip->ttl,rtt);

   return 0;
}
