/* 打印libnet动态库版本号 */
#include <stdio.h>
#include <libnet.h>

int main()
{
	printf("%s\n", libnet_version());
	return(0);
}

