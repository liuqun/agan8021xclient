/* 打印libpcap动态库版本号 */
#include <stdio.h>
#include <pcap/pcap.h>

int main()
{
	printf("%s\n", pcap_lib_version());
	return(0);
}

