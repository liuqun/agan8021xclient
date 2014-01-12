agan8021xclient说明文档：
===============================================
agan8021xclient仅支持H3C 802.1X client V2.20-0247私有加密认证，
本程序基于南理工学长AGanNo2写的H3C 802.1X客户端，做了部分修改以便于移植到OpenWRT路由器环境
安装后只有一个AGanNo2可执行文件，需要命令行指定802.1X登录用户名密码以及网卡
(网卡名称从命令行可以指定，也可以启动客户端后根据提示选择数字)，命令行格式如下：
AGanNo2 username password vlan1
或
AGanNo2 username password 

-----------------------------------------------
版本 v1.2-testing (updated on 2013.5.12)
