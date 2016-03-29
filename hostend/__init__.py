# -*- coding: utf-8 -*-
'''
	本模块主要功能为：在主机中创建docker容器并将容器的网络接口通过veth的方式连接到ovs网桥上
	在建立容器时，如果指定了该容器所属的命名空间，则应判断该命名空间是否创建与容器当前所属的主机上。
	如果该网络命名空间当前与容器属于同一个主机，则直接使用container模式构建容器网络
	如果该网路命名空间与容器不在同一个主机上，则应调用回调函数处理（此处即为向sdn控制器上报）
	如果没有指定网络命名空间，则应新生成一个网络命名空间，并通过回调函数上报
	此外本模块应配合控制器实现容器的动态迁移，具体机制见例图

	主要函数： 
		create_container : 创建容器 
			namespace : 对应的namespace ，默认为None
			interfaces[list] : 网络接口数组
			host : 对应的主机
			callback : 穿件完成后的回调函数，callback(container)
			belongsTo : 所属用户,默认为None
			返回新建的container对象

		create_namespace : 创建命名空间
			creator : 创建命名空间的容器
			belongsTo : 所属用户，默认为None
			callback : 回调函数

		move_data_to_host : 将数据向指定主机迁移
		    proxy : 容器程序代理
			container : 目标容器，为container对象
			destination : 目标主机，为host对象
			callback : 回调函数

	主要抽象： 
		Controller : 标识中央控制器类
		    report : 向中央控制器汇报相应事件

		    request : 向中央控制器请求相应消息





		Proxy : 容器创建代理
			create : 创建容器 - return container object
				bindingSwitch : 绑定的ovs交换机
				bindingNetns : 加入的namespace

				
			

'''