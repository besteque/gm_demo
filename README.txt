��˵����

1 CPU: X86_64

2 libs/http ��libgmurl��Դ�룬���������˽Կ���ģ���Ҫ�޸���ߵ�ip��ַ1.202.165.174(����)Ϊ WWW.CPKSAFE.COM �Ķ�Ӧ��ַ
  ���뷽�����ȱ��o�ļ��������ɾ�̬��
   gcc -c apply_2_server.c -o apply_2_server.o
   gcc -c cJSON.c -o cJSON.o
   ar -cr libgmurl.a apply_2_server.o cJSON.o 
   �澯��Ϣ���Ժ��ԡ�

3 ��ʾʱ��ֻ��Ҫ��iwall/svkd/target��������ʾ���� Ŀ¼�ṹ���ܱ䣬������ļ�·������

4 �����������滻����
	1) res\iwall
	2) code\security\include\apkapi.h
	3) �滻security\include�е�apply_2_server.h/cJSON.h
	4 libs\libgmapi.a  libgmurl.a (�޸���Կ���ĵ�ַ���μ�2)

5 �ͻ���ʾ�����룺report\tcp_client

6 use "netstat -ntlp" to see port info

7 ִ�з�����gm_demo# ./target/secureGW 80911   �����Ķ˿ڿ���ͨ������ָ�����˿�Ҫ��ǰ�����������
----------------------------------------
����ջ��
makefile
�ɱ����������
socke���
˫������
���ݷְ� --todo
�ֽ���ת�� --todo
���߳�
��/�̼߳�ͨѶ(LWT)
�ź��� (����)
typdef����ָ�룬�ص�
����ָ��/ָ������
websocket  ref:libs\http\apply_2_server.c
