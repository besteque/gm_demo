【说明】

1 CPU: X86_64

2 libs/http 是libgmurl的源码，如果连不上私钥中心，需要修改里边的ip地址1.202.165.174(两处)为 WWW.CPKSAFE.COM 的对应地址
  编译方法，先编出o文件，再生成静态库
   gcc -c apply_2_server.c -o apply_2_server.o
   gcc -c cJSON.c -o cJSON.o
   ar -cr libgmurl.a apply_2_server.o cJSON.o 
   告警信息可以忽略。

3 演示时，只需要将iwall/svkd/target拷贝到演示机。 目录结构不能变，否则打开文件路径错误。


4 北京发包，替换步骤
	1) res\iwall
	2) code\security\include\apkapi.h
	3 libs\libgmapi.a  libgmurl.a (修改密钥中心地址，参见2)

	
客户端示例代码：report\tcp_client
----------------------------------------
技术栈：
makefile
可变参数、宏变参
socke编程
双向链表
数据分包
字节序转换 --todo
多线程
进/线程间通讯(LWT)
信号量 (互斥)
typdef函数指针，回掉
二级指针/指针数组
websocket  ref:libs\http\apply_2_server.c
