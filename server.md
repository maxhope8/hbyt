bin目录下的init_local.sh文件

bash ./bin/init_local.sh 初始化环境

	运行之后在project/setting_env.py文件中生成环境变量，最终以这里的配置启动程序

启动后台：
	bash ./bin/fta.sh start  启动所有的进程

本地数据库配置:
    fta/conf/settings_local.py  数据，redis等配置   
    
关于故障自愈的一个简单流程：
	第一步：现在作业平台创建任务
    第二步：进入套餐管理创建新的套餐
    第三步：进入接入自愈，创建一个自愈，选择一个类型，同时选择上需要使用的套餐
    第四步：手动触发一个告警，比如restapi，通过作业平台快速执行脚本，将下面的案例复制，修改ip和alarm_type
    第五步：手动触发之后，rest——api就会接收到，这个时候就会执行你在套餐过程中选择的呢个脚本
    注意：其中他会使用告警的ip去替换，执行脚本的ip，意思就是，自愈脚本会在产生错误的主机上执行
    
    
pool_alarm # 拉去告警
	启动的是 fta/pool_alarm/mian文件
	手动推送类：
	manage/www/zabbix.py
    
    主动拉去类：
        project/pool_alarm/bk_monitor.py
        里面通过一个类重新定义了pull_alarm方法，之后通过fta/poll_alarm/main.py中的start_poll_alarm调用		这个模块
match_alarm  # 匹配告警
	fta/match_alarm/main.py函数
converge # 告警收敛进程
	fta/converge/main.py函数
    将每次获取到的告警放入redis中，通过告警收敛规则进行匹配，如果达到规则就run一下，之后根据指定的规则跳过或者汇总等等，之后放入队列
collect # 告警汇总进程

solution # 自愈套餐进程
	fta/solution/main.py
    其中从SOLUTION_QUEUE套餐队列中获取事件的id，通过事件的id过去到告警的实例，以为可能存在组合套餐的情况所以，将套餐的节点信息放入任务JOB_QUEUE队列中。
    
    
job  # 处理自愈套餐节点信息，推送到jobserver进行更多操作
	fta/job/main.py
    关于自定义套餐类型：第一步下载web——app下的web_app/fta_solutions_app/fta_std.py中的SOLUTION_TYPE_CHOICES中定义一个test，然后去server端的manager/soulution/创建一个test.py文件拷贝一下其他同目录的代码就可以了。
    # 其中套餐和job关联非常紧密，所以看起来有点麻烦，根据节点执行
    
jobserver # 执行自愈套餐的某个节点
	fta/www/apipservice
scheduler # 调度进程，发送邮件等进程
polling # 拉去任务接口
qos # 定期查询beanstalked通道的告警，是否超时
logging # 进程日志
-------------------------------------------------------------------------------------
定时任务：
	其中预警详情和自愈助手的数据都是来自定时任务
