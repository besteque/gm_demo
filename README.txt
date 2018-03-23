【说明】

1 CPU: X86_64

2 libs/http 是libgmurl的源码，如果连不上私钥中心，需要修改里边的ip地址1.202.165.174(两处)为 WWW.CPKSAFE.COM 的对应地址
  编译方法，先编出o文件，再生成静态库
   gcc -c apply_2_server.c -o apply_2_server.o
   gcc -c cJSON.c -o cJSON.o
   ar -cr libgmurl.a apply_2_server.o cJSON.o 
   告警信息可以忽略。

3 演示时，只需要将iwall/svkd/target拷贝到演示机。 目录结构不能变，否则打开文件路径错误。
