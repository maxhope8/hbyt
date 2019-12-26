#!/bin/bash
# Auther Michael
divider=##################################################################
declare -A dict_sample
dict_sample=([Pri]="/usr/bin/bazh" [shell]="/tmp/.beac" [conf]="/tmp/.c.ini" [mail.xjsbweb.com]="/usr/sbin/prel" [s.rammus.me]="/usr/sbin/rpcgssd" [s.rammus.me-2]="/usr/sbin/ntpcheck")
s_date=`date +%Y-%m-%d-%H:%M:%S`
ip=`ifconfig | grep -oE 'inet addr.([0-9]{1,3}\.?){4}\>' | grep -v "127\." | grep -oE '([0-9]{1,3}\.?){4}' | head -n 1`
Directory=/tmp/checklinux_6_fall5_$ip.log
if [ -f $Directory ]; then
    rm -f $Directory
fi
# ----------------
echo "The Script begin at $s_date."
echo "The Script begin at $s_date." >> $Directory
echo "<Ip>$ip</Ip>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>01.Check UID is 0</Name>" >> $Directory
echo "<Name>01.检查UID为0的账户</Name>" >> $Directory
echo "<Code>awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd</Code>" >> $Directory
echo "<Results>" >> $Directory
awk -F: '($3 == 0) { print $1 }' /etc/passwd >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>02.Check UID is same</Name>" >> $Directory
echo "<Name>02.检查UID相同的账户</Name>" >> $Directory
echo "<Code>more /etc/passwd | grep \$uid | awk -F: '{print \$1}' 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
uid=`awk -F: '{a[$3]++}END{for(i in a)if(a[i]>1)print i}' /etc/passwd`
if [ -n "$uid" ]; then
    more /etc/passwd | grep $uid | awk -F: '{print $1}' 2>/dev/zero >> $Directory
fi
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>03.Check Permission to login</Name>" >> $Directory
echo "<Name>03.检查可以登录的账户</Name>" >> $Directory
echo "<Code>more /etc/passwd | grep -v 'nologin'</Code>" >> $Directory
echo "<Results>" >> $Directory
more /etc/passwd | grep -v 'nologin' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>04.Check Non-default user</Name>" >> $Directory
echo "<Name> 04.检查非默认账户</Name>" >> $Directory
echo "<Code>gawk -F: '{if ($3>='\$uid2' && \$3!=65534) {print \$1}}' /etc/passwd 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
uid2=$(grep "^UID_MIN" /etc/login.defs | awk '{print $2}')
if [ -n "$uid2" ]; then
    gawk -F: '{if ($3>='$uid2' && $3!=65534) {print $1}}' /etc/passwd 2>/dev/zero >> $Directory
fi
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>05.Check Non-passowrd user</Name>" >> $Directory
echo "<Name>05.检查空密码账户</Name>" >> $Directory
echo "<Code>gawk -F: '(\$2==\"\") {print \$1}' /etc/shadow</Code>" >> $Directory
echo "<Results>" >> $Directory
gawk -F: '($2=="") {print $1}' /etc/shadow >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>06.Check Root loginSSH permissions</Name>" >> $Directory
echo "<Name>06.检查允许Root登录SSH权限的账户</Name>" >> $Directory
echo "<Code>more /etc/ssh/sshd_config | grep PermitRootLogin | grep -v '^#'</Code>" >> $Directory
echo "<Results>" >> $Directory
more /etc/ssh/sshd_config | grep PermitRootLogin | grep -v '^#' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>07.Check System history commond</Name>" >> $Directory
echo "<Name>07.检查执行系统命令历史记录</Name>" >> $Directory
echo "<Code>more /root/.bash_history</Code>" >> $Directory
echo "<Results>" >> $Directory
more /root/.bash_history >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>08.Check Database history commond</Name>" >> $Directory
echo "<Name>08.检查执行数据库命令历史记录</Name>" >> $Directory
echo "<Code>more /root/.mysql_history 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
more /root/.mysql_history 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>09.Check Inspection process</Name>" >> $Directory
echo "<Name>09.检查进程</Name>" >> $Directory
echo "<Code>ps -eHo euser,uid,pid,ppid,%cpu,%mem,lstart,tty,etime,time,stat,comm,args</Code>" >> $Directory
echo "<Results>" >> $Directory
ps -eHo euser,uid,pid,ppid,%cpu,%mem,lstart,tty,etime,time,stat,comm,args >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>10.Check Daemon process</Name>" >> $Directory
echo "<Name>10.检查Xinetd服务</Name>" >> $Directory
echo "<Code>more /etc/xinetd.d/rsync 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
more /etc/xinetd.d/rsync 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>11.Check hosts info</Name>" >> $Directory
echo "<Name>11.检查hosts文件</Name>" >> $Directory
echo "<Code>more /etc/hosts</Code>" >> $Directory
echo "<Results>" >> $Directory
more /etc/hosts >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>12.Check Public key</Name>" >> $Directory
echo "<Name>12.检查公钥</Name>" >> $Directory
echo "<Code>more /root/.ssh/*.pub 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
more /root/.ssh/*.pub 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>13.Check Private key</Name>" >> $Directory
echo "<Name>13.检查私钥</Name>" >> $Directory
echo "<Code>more /root/.ssh/id_rsa 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
more /root/.ssh/id_rsa 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>14.Check Script file</Name>" >> $Directory
echo "<Name>14.检查脚本文件</Name>" >> $Directory
echo "<Code>find /bin /sbin /home /usr/bin /usr/sbin /usr/local /tmp -maxdepth 3 -name "\*\.\*" 2>/dev/zero | egrep '\.(py|sh|per|pl)\$' | xargs md5sum</Code>" >> $Directory
echo "<Results>" >> $Directory
find /bin /sbin /home /usr/bin /usr/sbin /usr/local /tmp -maxdepth 3 -name "*.*" 2>/dev/zero | egrep '\.(py|sh|per|pl)$' | xargs md5sum >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>15.Check Modified files in 24h</Name>" >> $Directory
echo "<Name>15.检查最近一天的修改文件</Name>" >> $Directory
echo "<Code>find /bin /sbin /home /usr/bin /usr/sbin /usr/local /tmp -mtime 0 2>/dev/zero | grep -E '\.(py|sh|per|pl|php|asp|jsp)$' | xargs md5sum</Code>" >> $Directory
echo "<Results>" >> $Directory
find /bin /sbin/ /home /usr/bin /usr/sbin /usr/local /tmp -mtime 0 2>/dev/zero | grep -E '\.(py|sh|per|pl|php|asp|jsp)$' | xargs md5sum >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>16.Check the TCP connection</Name>" >> $Directory
echo "<Name>16.检查TCP连接</Name>" >> $Directory
echo "<Code>netstat -antlp</Code>" >> $Directory
echo "<Results>" >> $Directory
netstat -antlp >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>17.Check the UDP connection</Name>" >> $Directory
echo "<Name>17.检查UDP连接" >> $Directory
echo "<Code>netstat -anulp</Code>" >> $Directory
echo "<Results>" >> $Directory
netstat -anulp >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>18.check unix process</Name>" >> $Directory
echo "<Name>18.检查 unix 连接</Name>" >> $Directory
echo "<Code>netstat -nxlp</Code>" >> $Directory
echo "<Results>" >> $Directory
netstat -nxlp >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>19.Check Reflect shell for netstat</Name>" >> $Directory
echo "<Name>19.检查正在连接的bash</Name>" >> $Directory
echo "<Code>netstat -antlp | grep EST | grep bash</Code>" >> $Directory
echo "<Results>" >> $Directory
netstat -antlp | grep EST | grep bash >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>20.Check New user</Name>" >> $Directory
echo "<Name>20.检查新建账户日志</Name>" >> $Directory
echo "<Code>more /var/log/secure* | grep 'new user' | awk '{print \$8}' | awk -F '[=,]' '{print \$2}' | sort | uniq -c</Code>" >> $Directory
echo "<Results>" >> $Directory
more /var/log/secure* | grep 'new user' | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>21.Check New user group</Name>" >> $Directory
echo "<Name>21.检查新建用户组日志</Name>" >> $Directory
echo "<Code>more /var/log/secure* | grep 'new group' | awk '{print \$8}' | awk -F '[=,]' '{print \$2}' | sort | uniq -c</Code>" >> $Directory
echo "<Results>" >> $Directory
more /var/log/secure* | grep 'new group' | awk '{print $8}' | awk -F '[=,]' '{print $2}' | sort | uniq -c >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>22.Successful Login info</Name>" >> $Directory
echo "<Name>22.检查SSH登录成功日志</Name>" >> $Directory
echo "<Code>grep 'Accepted' /var/log/secure* | awk '{print \$11}' | sort | uniq -c | sort -nr</Code>" >> $Directory
echo "<Results>" >> $Directory
grep 'Accepted' /var/log/secure* | awk '{print $11}' | sort | uniq -c | sort -nr >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>23.Failed Login info</Name>" >> $Directory
echo "<Name>23.检查登录失败日志</Name>" >> $Directory
echo "<Code>grep 'Failed' /var/log/secure* | awk '{print \$11}' | sort | uniq -c | sort -nr</Code>" >> $Directory
echo "<Results>" >> $Directory
grep 'Failed' /var/log/secure* | awk '{print $11}' | sort | uniq -c | sort -nr >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>24.Check Time cron to download</Name>" >> $Directory
echo "<Name>24.检查计划任务日志-下载</Name>" >> $Directory
echo "<Code>more /var/log/cron* | grep 'wget|curl'</Code>" >> $Directory
echo "<Results>" >> $Directory
more /var/log/cron* | grep 'wget|curl' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>25.Check Time cron to run</Name>" >> $Directory
echo "<Name>25.检查计划任务日志-运行</Name>" >> $Directory
echo "<Code>more /var/log/cron* | grep -E '\.py\$|\.sh\$|\.pl\$'</Code>" >> $Directory
echo "<Results>" >> $Directory
more /var/log/cron* | grep -E '\.py$|\.sh$|\.pl$' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>26.Check Start Tasks</Name>" >> $Directory
echo "<Name>26.检查服务启动项</Name>" >> $Directory
echo "<Code>chkconfig --list | grep on | awk '{print \$1}' | grep -E '\.(sh|per|py)\$'</Code>" >> $Directory
echo "<Results>" >> $Directory
chkconfig --list | grep on | awk '{print $1}' | grep -E '\.(sh|per|py)$'>> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>27.Check Scheduled Tasks</Name>" >> $Directory
echo "<Name>27.检查计划任务</Name>" >> $Directory
echo "<Code>egrep '((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)\$))' /etc/cron*/* /var/spool/cron/* 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
egrep '((chmod|useradd|groupadd|chattr)|((wget|curl)*\.(sh|pl|py)$))' /etc/cron*/* /var/spool/cron/* 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>28.Check SSH stat</Name>" >> $Directory
echo "<Name>28.检查SSH状态</Name>" >> $Directory
echo "<Code>stat /usr/sbin/sshd</Code>" >> $Directory
echo "<Results>" >> $Directory
ssh -V &>> $Directory
stat /usr/sbin/sshd >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>29.Check Installed abnormal info</Name>" >> $Directory
echo "<Name>29.检查危险软件或工具</Name>" >> $Directory
echo "<Code>rpm -qa  | awk -F- '{print \$1}' | sort | uniq | grep -E '^(ncat|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)$'</Code>" >> $Directory
echo "<Results>" >> $Directory
rpm -qa  | awk -F- '{print $1}' | sort | uniq | grep -E '^(ncat|sqlmap|nmap|beef|nikto|john|ettercap|backdoor|proxy|msfconsole|msf)$' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>30.Check RPM check</Name>" >> $Directory
echo "<Name>30.检查RPM套件</Name>" >> $Directory
echo "<Code>rpm -Va 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
rpm -Va 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>31.Check Network share</Name>" >> $Directory
echo "<Name>31.检查网络共享</Name>" >> $Directory
echo "<Code>exportfs 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
exportfs 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>32.Check httpd logs attack behavior</Name>" >> $Directory
echo "<Name>32.检查可疑Web日志-Tools</Name>" >> $Directory
echo "<Code>egrep '(select|script|acunetix|sqlmap)' /var/log/httpd/access_log 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
egrep '(select|script|acunetix|sqlmap)' /var/log/httpd/access_log 2>/dev/zero >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>33.Display Post request</Name>" >> $Directory
echo "<Name>33.检查可疑Web日志-POST</Name>" >> $Directory
echo "<Code>more /var/log/httpd/access_log 2>/dev/zero | grep 'POST' | awk '{print \$1}' | sort | uniq -c | sort -nr>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
more /var/log/httpd/access_log 2>/dev/zero | grep 'POST' | awk '{print $1}' | sort | uniq -c | sort -nr >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>34.Filter Content-Length more than 1.5kb</Name>" >> $Directory
echo "<Name>34.检查可疑Web日志-长度</Name>" >> $Directory
echo "<Code>awk '{if(\$10>1500){print \$0}}' /var/log/httpd/access_log 2>/dev/zero | grep POST | grep 200 | grep php</Code>" >> $Directory
echo "<Results>" >> $Directory
awk '{if($10>1500){print $0}}' /var/log/httpd/access_log 2>/dev/zero | grep POST | grep 200 | grep php >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>35.Check malicious sample</Name>" >> $Directory
echo "<Name>35.检查恶意样本</Name>" >> $Directory
echo "<Code>Check malicious sample</Code>" >> $Directory
echo "<Results>" >> $Directory
for sample in $(echo ${!dict_sample[*]})
do
    tmp=`stat ${dict_sample[$sample]} 2>/dev/zero`
    if [ -n "$tmp" ]; then
        echo -e "\n!!! Found sample !!!" $sample >> $Directory
        echo "$tmp" >> $Directory
    fi
done
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>36.Check Logged user</Name>" >> $Directory
echo "<Name>36.检查当前账户登录信息</Name>" >> $Directory
echo "<Code>w</Code>" >> $Directory
echo "<Results>" >> $Directory
w >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>37.Check Recent login info</Name>" >> $Directory
echo "<Name>37.检查所有账户最近多次登录信息</Name>" >> $Directory
echo "<Code>last</Code>" >> $Directory
echo "<Results>" >> $Directory
last >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>38.Check All user login info</Name>" >> $Directory
echo "<Name>38.检查所有账户最近一次登录信息</Name>" >> $Directory
echo "<Code>lastlog | grep -v '\*\*'</Code>" >> $Directory
echo "<Results>" >> $Directory
lastlog | grep -v "\*\*" >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>39.Check Allow remote access</Name>" >> $Directory
echo "<Name>39.检查白名单</Name>" >> $Directory
echo "<Code>more /etc/hosts.allow | grep -v '#' 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
more /etc/hosts.allow 2>/dev/zero | grep -v '#' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>40.Check Deny remote access</Name>" >> $Directory
echo "<Name>40.检查黑名单</Name>" >> $Directory
echo "<Code>more /etc/hosts.deny | grep -v '#' 2>/dev/zero</Code>" >> $Directory
echo "<Results>" >> $Directory
more /etc/hosts.deny 2>/dev/zero | grep -v '#' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>41.Check DNS info</Name>" >> $Directory
echo "<Name>41.检查DNS配置信息</Name>" >> $Directory
echo "<Code>more /etc/resolv.conf | grep ^nameserver | awk '{print \$NF}'</Code>" >> $Directory
echo "<Results>" >> $Directory
more /etc/resolv.conf | grep ^nameserver | awk '{print $NF}' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>42.Check DNS use info</Name>" >> $Directory
echo "<Name>42.检查DNS日志信息</Name>" >> $Directory
echo "<Code>more /var/log/messages* | grep 'using nameserver' | awk '{print \$NF}' | awk -F# '{print \$1}' | sort | uniq</Code>" >> $Directory
echo "<Results>" >> $Directory
more /var/log/messages* | grep 'using nameserver' | awk '{print $NF}' | awk -F# '{print $1}' | sort | uniq >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>43.Check Network connection</Name>" >> $Directory
echo "<Name>43.检查网络连接</Name>" >> $Directory
echo "<Code>netstat -ant |grep '^tcp'|awk '{print \$6}'|sort|uniq -c</Code>" >> $Directory
echo "<Results>" >> $Directory
netstat -ant |grep '^tcp'|awk '{print $6}'|sort|uniq -c >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>44.Check Routing forward</Name>" >> $Directory
echo "<Name>44.检查路由</Name>" >> $Directory
echo "<Code>more /proc/sys/net/ipv4/ip_forward</Code>" >> $Directory
echo "<Results>" >> $Directory
more /proc/sys/net/ipv4/ip_forward >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>45.Check Kernel abnormal info</Name>" >> $Directory
echo "<Name>45.检查非法内核信息</Name>" >> $Directory
echo "<Code>lsmod | grep -Ev 'ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state'</Code>" >> $Directory
echo "<Results>" >> $Directory
lsmod | grep -Ev 'ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6table_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state' >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>46.View High CPU info</Name>" >> $Directory
echo "<Name>46.检查高CPU占用</Name>" >> $Directory
echo "<Code>ps -aux 2>/dev/zero | grep -v '^USER' | sort -nr -k 3 | head -5</Code>" >> $Directory
echo "<Results>" >> $Directory
ps -aux 2>/dev/zero | grep -v '^USER' | sort -nr -k 3 | head -5 >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>47.View High MEM info</Name>" >> $Directory
echo "<Name>47.检查高内存占用</Name>" >> $Directory
echo "<Code>ps -aux 2>/dev/zero | grep -v '^USER' | sort -nr -k 4 | head -5</Code>" >> $Directory
echo "<Results>" >> $Directory
ps -aux 2>/dev/zero | grep -v '^USER' | sort -nr -k 4 | head -5 >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>48.View Environment variables</Name>" >> $Directory
echo "<Name>48.检查环境变量</Name>" >> $Directory
echo "<Code>env</Code>" >> $Directory
echo "<Results>" >> $Directory
env >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>49.Check resource info</Name>" >> $Directory
echo "<Name>49.检查资源情况</Name>" >> $Directory
echo "<Code>lscpu&free -g&df -hl</Code>" >> $Directory
echo "<Results>" >> $Directory
lscpu >> $Directory
free -g >> $Directory
df -hl>> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
echo "<Name>50.Check Files MD5</Name>" >> $Directory
echo "<Name>50.检查文件MD5</Name>" >> $Directory
echo "<Code>md5sum /usr/*bin/*</Code>" >> $Directory
echo "<Results>" >> $Directory
md5sum /usr/*bin/* >> $Directory
echo "</Results>" >> $Directory
echo $divider >> $Directory
# ----------------
e_date=`date +%Y-%m-%d-%H:%M:%S`
echo "The Script end at $e_date." >> $Directory
echo "All Done!"
