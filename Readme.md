# msglogger

		github�����������ڼ�¼objc_msgSend��Ϣ�Ĳֿ⣬Ȼ��������һ������
		1.ʹ��dyld_insertlibrary��ʽ��������������ios app
		2.ʹ��substrate����ǳ���Ȼ����new_objc_msgSend�ص�������̫����������Ч�ʺܵ�(�����Snoop-it)
		3.��new_objc_msgSend�ص�ʵ����.m/.mm�ļ��У����µݹ�(��Ϊ�����������ɾֲ����������������룬����Ҳ���õ�objc_msgSend)(�����InspectiveC)����ʵ����c/cpp���򲻻��еݹ�����
		4.δ�ܽ���objc_msgSend����
		���ڴ����⣬�ṩ�Ľ��������
		1.ʹ��cydia substrate���ʵ��msgsend hook�Լ�Cydia�ṩ��MobileLoader�Զ�����dylibģ�飨ע��ios�豸�ϴ��ڵ�substrateͷ�ļ�����ȫ�ģ�
		2.new_objc_msgSend�ص������첽����ʽ�����selector�ĵ�ַ�ռ��Ƿ�λ�ڸ�ģ�飬������ƥ��id��selector��ö�
		3.��.c/.cpp��ʵ��new_objc_msgSend�ص�
		4.��signature�������������ͣ�����ƥ��Ҫclass+selector�������ù����򲻿ɱ���ĺ�ʱ��
		
		msgloggerʹ�÷�ʽ��
		./utilityserver --app_inject "com.?"
		/tmp/msglog.txt�鿴���
		
		���ڵ����⣺
		���ڴ�Ŀ�ִ���ļ�����msgSend�൱Ƶ������˲��Ƽ�hook msgSend��ʽ�����Կ���ʹ��frida��cycript hookĳЩselector
		