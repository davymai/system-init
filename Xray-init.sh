#!/bin/sh
#################################################
#  --Info
#      Xray Server Initialization CentOS 7.x script
#################################################
#   File: CentOS7-init.sh
#
#   Usage: bash CentOS-Xray-init.sh
#
#   Author: 大威(Davy) ( i[at]davymai.com )
#
#   Link: https://github.com/davymai/CentOS-init
#
#   Version: 2.90
#################################################
# 设置参数
. /etc/rc.d/init.d/functions
export LANG=zh_CN.UTF-8
export PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin

# 初始化脚本设置 {{{
Color_off='\033[0m' # 重置文字

# 常规颜色
Black='\033[0;30m'  # 黑色
Red='\033[0;31m'    # 红色
Green='\033[0;32m'  # 绿色
Yellow='\033[0;33m' # 黄色
Blue='\033[0;34m'   # 蓝色
Purple='\033[0;35m' # 紫色
Cyan='\033[0;36m'   # 青色
White='\033[0;37m'  # 白色

# 加粗颜色
BBlack='\033[1;30m'  # 黑色
BRed='\033[1;31m'    # 红色
BGreen='\033[1;32m'  # 绿色
BYellow='\033[1;33m' # 黄色
BBlue='\033[1;34m'   # 蓝色
BPurple='\033[1;35m' # 紫色
BCyan='\033[1;36m'   # 青色
BWhite='\033[1;37m'  # 白色

# 版本信息
VERSION='2.90'
# 系统信息
SYSTEM="$(uname -s)"
INFO=$(cat /etc/redhat-release)
MYIP=$(curl -s ip.sb)
ipadd=$(ifconfig | awk '/^[0-9]+: / {}; /inet.*global/ {print gensub(/(.*)\/(.*)/, "\\1", "g", $2)}')
#ShellFolder=$(cd "$(dirname -- "$0")" || exit pwd)

# 成功/信息/错误/警告 文字颜色设置 {{{
msg() {
  printf '%b\n' "$1" >&2
}

info() {
  msg "${Blue}[➭]${Color_off} ${1}${2}"
}

cont() {
  msg "${Yellow}[►]${Color_off} ${1}${2}"
}

warn() {
  msg "${Red}[✘]${Color_off} ${1}${2}"
}
error() {
  msg "${Red}[✘]${Color_off} ${1}${2}"
  exit 1
}
success() {
  msg "${Green}[✔]${Color_off} ${1}${2}"
}

welcome() {
  clear
  msg "${Cyan}
  +------------------------------------------------------------------------+
  |                           CentOS 7.x 初始化脚本                        |
  |                       初始化系统以确保安全性和性能                     |
  +------------------------------------------------------------------------+
        System:  ${INFO%\\l}    Version: ${VERSION}    
        updated date: 2023-04-19                         by: 大威(Davy)

                     初始化脚本 ${BRed}5 ${Cyan}秒后开始, 按 ${Green}ctrl C ${Cyan}取消
${Color_off}"
  sleep 6
}

# 检查用户是否为 root
if [ "$(id -u)" != "0" ]; then
  error "错误: 请使用 root 用户身份来初始化系统！"
fi

# 初始化计时开始
startTime=$(date +%Y%m%d-%H:%M)
startTime_s=$(date +%s)

# 配置DNS优化
config_nameserver() {
  info "*** 优化 DNS 解析性能 ***"
  #ns_nu_check=$(grep -c nameserver /etc/resolv.conf)
  #ns_cf_check=$(grep -c 8.8.4.4 /etc/resolv.conf)
  #ns_opt_check=$(grep -c options /etc/resolv.conf)
  # nameserver 大于等于 2
  #if [ "$ns_nu_check" -ge 2 ]; then
  #  cont "DNS已存在..."
  #else
  #grep "options" /etc/resolv.conf >>/dev/null
  #if [ $? -eq 0 ]; then
  if [ "$ns_cf_check" -eq 0 ] && [ "$ns_opt_check" -eq 0 ]; then
    cont "添加 ${Green}Google DNS${Color_off} 和 DNS 查询规则..."
    sed -i '$ a\nameserver 8.8.4.4\noptions timeout:1 attempts:3 single-request-reopen' /etc/resolv.conf
  elif [ "$ns_cf_check" -eq 0 ] && [ "$ns_opt_check" -eq 1 ]; then
    cont "添加 ${Green}Google DNS${Color_off} ..."
    sed -i '$ i\nameserver 8.8.4.4' /etc/resolv.conf
  elif [ "$ns_cf_check" -eq 1 ] && [ "$ns_opt_check" -eq 0 ]; then
    cont "添加 DNS 查询规则..."
    sed -i '$ a\options timeout:1 attempts:3 single-request-reopen' /etc/resolv.conf
  else
    warn "${Green}Google DNS${Color_off}已存在。"
  fi
  success "DNS性能优化完成。\n"
  #fi
}

# 更新系统
system_update() {
  info "*** 更新系统 ***"
  # 云服务器注释设置开始
  # 备份 yum 源镜像文件 **本地服务器必须打开注释， 做好备份!**
  cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak.$(date +%F)-$(awk 'BEGIN { srand(); print int(rand()*32768) }' /dev/null) >/dev/null >/dev/null 2>&1
  cont "更换 yum 源镜像为${BYellow}清华大学${Color_off}镜像..."
  sed -e 's|^mirrorlist=|#mirrorlist=|g' \
    -e 's|^#baseurl=http://mirror.centos.org|baseurl=https://mirrors.tuna.tsinghua.edu.cn|g' \
    -i.bak \
    /etc/yum.repos.d/CentOS-*.repo
  #cont "更换 yum 源镜像为${BYellow}阿里云${Color_off}镜像..."
  #curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo
  #cont "更换 yum 源镜像为${BYellow}腾讯云${Color_off}镜像..."
  #curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.cloud.tencent.com/repo/centos7_base.repo
  #备份 epel 源镜像文件 **本地服务器必须打开注释， 做好备份!**
  cp /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel.repo.backup.$(date +%F)-$(awk 'BEGIN { srand(); print int(rand()*32768) }' /dev/null) >/dev/null 2>&1
  cont "添加 ${BYellow}epel${Color_off} 源为${BYellow}清华大学${Color_off}镜像..."
  yum install -y epel-release
  sed -e 's!^metalink=!#metalink=!g' \
    -e 's!^#baseurl=!baseurl=!g' \
    -e 's!//download\.fedoraproject\.org/pub!//mirrors.tuna.tsinghua.edu.cn!g' \
    -e 's!//download\.example/pub!//mirrors.tuna.tsinghua.edu.cn!g' \
    -e 's!http://mirrors!https://mirrors!g' \
    -i /etc/yum.repos.d/epel*.repo
  #cont "添加 epel ${BYellow}阿里云${Color_off}镜像..."
  #curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
  #cont "添加 epel ${BYellow}腾讯云${Color_off}镜像..."
  #curl -o /etc/yum.repos.d/epel.repo http://mirrors.cloud.tencent.com/repo/epel-7.repo
  # 云服务器注释设置结束
  cont "开始更新系统..."
  yum makecache fast && yum update -y && yum -y upgrade
  success "系统更新完成。\n"
}

# 安装软件工具包
install_tools() {
  info "*** 安装工具包 ***"
  # LSB 标准化，提升兼容性
  cont "正在安装 ${BYellow}LSB 提升兼容性${Color_off} ..."
  command -v lsb_release >/dev/null 2>&1 || {
    if
      [ -e "/etc/euleros-release" ]
    then
      yum -y install euleros-lsb || yum -y install redhat-lsb-core
    fi
  }
  # 安装 gcc
  #cont "正在安装 ${BYellow}gcc${Color_off} ..."
  #command -v gcc >/dev/null 2>&1 || yum -y install gcc
  # 安装 openssh-server openssh-clients
  #yum -y install openssh-server openssh-clients
  # 安装 vim authconfig libselinux-utils initscripts net-tools
  #yum install -y vim authconfig libselinux-utils initscripts net-tools
  # 安装 wget vim net-tools htop supervisor
  cont "正在安装 ${BYellow}wget vim zip unzip lrzsz net-tools htop supervisor${Color_off} ...\n"
  yum install -y wget vim zip unzip lrzsz net-tools htop socat
  # supervisor 进程管理
  #yum install -y supervisor
  #echo ''
  #cont "正在启动 ${BGreen}supervisor${Color_off} ..."
  #systemctl enable supervisord
  #if ! systemctl start supervisord; then
  #  error "supervisor 启动失败, 请检查配置。\n"
  #else
  #  success "软件工具包安装完成。\n"
  #fi
  success "软件工具包安装完成。\n"
}

# 删除无用的用户和组
delete_useless_user() {
  info "*** 删除无用的用户和用户组 ***"
  userdel -r adm
  userdel -r lp
  userdel -r games
  userdel -r ftp
  groupdel lp
  groupdel games
  groupdel video
  groupdel ftp
  success "删除无用的用户和用户组完成。\n"
}

# 禁用不使用服务
disable_services() {
  info "*** 精简开机启动 ***"
  cont "正在禁用 ${BRed}postfix${Color_off} 服务..."
  systemctl disable auditd.service
  systemctl disable postfix.service
  systemctl disable dbus-org.freedesktop.NetworkManager.service
  echo '#systemctl list-unit-files | grep -E "auditd|postfix|dbus-org\.freedesktop\.NetworkManager"'
 systemctl list-unit-files | grep -E "auditd|postfix|dbus-org\.freedesktop\.NetworkManager"
  success "完成精简开机启动\n"
}

# 密码规则配置
config_password() {
  info "*** 设置密码规则，提升安全性 ***"
  cont "正在设置密码规则..."
  # /etc/login.defs  /etc/security/pwquality.conf
  sed -i "/PASS_MIN_LEN/s/5/8/g" /etc/login.defs
  #at least 8 character
  authconfig --passminlen=8 --update
  #at least 2 kinds of Character class
  authconfig --passminclass=2 --update
  #at least 1 Lowercase letter
  authconfig --enablereqlower --update
  #at least 1 Capital letter
  authconfig --enablerequpper --update
  success "密码规则设置完成 (8个字符, 必须包含大小写字母)\n"
}

# 为 root 用户添加公钥
root_sshkey() {
  info "*** 为 root 用户添加公钥 ***"
  printf "请输入您的公钥: "
  read -r root_rsa
  root_ssh_path="/root/.ssh"
  root_auth_file="/root/.ssh/authorized_keys"
  if [ ! -d "$root_ssh_path" ]; then
    mkdir -p /root/.ssh && chmod 700 /root/.ssh && cd /root/.ssh || exit
  fi
  if [ ! -f "$root_auth_file" ]; then
    touch "$root_auth_file"
  fi
  if test -s /root/.ssh/authorized_keys; then
    sed -i '$a/'"$root_rsa"'' /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  else
    echo "$root_rsa" >>/root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  fi
  success "为 root 用户添加公钥完成。\n"
}

# 创建新用户
create_user() {
  info "*** 创建新用户 ***"
  while :; do
    read -p "用户名: " user_name
    if [[ "$user_name" =~ .*root.* || "$user_name" =~ .*admin.* ]]; then
      warn "用户名不能以 ${BRed}admin${Color_off} 或 ${BRed}root${Color_off} 开头, 请重新输入\n"
    elif [ "$user_name" = "" ]; then
      warn "用户名不能为<空>, 请重新输入\n"
    else
      break
    fi
  done
  while :; do
    read -p "输入密码(密码输入已隐藏): " -s user_pass
    echo ''
    read -p "再次确认密码: " -s user_passwd
    echo ''
    if [ "$user_pass" != "$user_passwd" ]; then
      warn "两次密码验证失败, 请重新输入\n"
    elif [ "$user_passwd" = "" ]; then
      warn "密码不能为<空>, 请重新输入\n"
    else
      break
    fi
  done
  # 为新增用户添加公钥
  printf "请输入您的公钥: "
  read -r user_rsa
  useradd -G wheel "$user_name" && echo "$user_passwd" | passwd --stdin "$user_name" >/dev/null 2>&1
  cd /home/"$user_name" && mkdir -p .ssh && chown "$user_name":"$user_name" .ssh && chmod 700 .ssh && cd .ssh || exit
  echo "$user_rsa" >>authorized_keys && chown "$user_name":"$user_name" authorized_keys && chmod 600 authorized_keys
  echo "$user_name ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
  success "用户: ${BGreen}$user_name${Color_off} 创建完成。"
  # 为 root 添加用户公钥
  cont "为 root 添加用户公钥..."
  if test -s /root/.ssh/authorized_keys; then
    sed -i '$a/'"$user_rsa"'' /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  else
    echo "$user_rsa" >>/root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  fi
  success "为 root 添加用户公钥完成。\n"
}

# 配置 ssh 权限
config_sshd() {
  info "*** 开始配置 SSH 权限 ***"
  # 输入错误密码时锁定用户 root 10s 其他 180s
  cont "正在设置密码错误锁定规则..."
  sed -i '1a auth       required     pam_tally2.so deny=3 unlock_time=600 even_deny_root root_unlock_time=180' /etc/pam.d/sshd
  success "用户密码错误锁定规则完成。\nroot用户锁定: ${BRed}3${Color_off}分钟\n其他用户锁定: ${BRed}10${Color_off}分钟"
  cont "设置 SSH 端口..."
  while :; do
    printf "请输入 SSH 端口号(留空默认: 22): "
    read -r ssh_port
    if [ "${ssh_port}" = "" ]; then
      ssh_port="22"
    fi
    if [[ ! $ssh_port =~ ^[0-9]+$ ]]; then
      warn "端口仅支持${Red}数字${Color_off}, 请重新输入!\n"
    elif [ "${ssh_port}" -gt "65535" ]; then
      warn "端口号不能超过 ${Red}65535${Color_off}, 请重新输入!\n"
    else
      break
    fi
  done
  sed -i '/^#Port/s/#Port 22/Port '"$ssh_port"'/g' /etc/ssh/sshd_config
  sed -i '/^#UseDNS/s/#UseDNS yes/UseDNS no/g' /etc/ssh/sshd_config
  # 禁用密码登陆
  #sed -i '/^PasswordAuthentication yes/s/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
  sed -i '/^#PubkeyAuthentication/s/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
  sed -i 's/UsePAM.*/UsePAM yes/g' /etc/ssh/sshd_config
  sed -i '/^GSSAPIAuthentication/s/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' /etc/ssh/sshd_config
  sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
  # 如果不想让root登录，请在下面打开注释
  #sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

  if ! systemctl restart sshd; then
    error "sshd 重启失败, 请检查配置。\n"
  else
    success "SSH 端口设置完成。\n"
  fi
}

# 配置 bashrc
config_bashrc() {
  info "***配置 bashrc alias ***"
  cp -f /etc/bashrc /etc/bashrc.bak.$(date +%F)-$(awk 'BEGIN { srand(); print int(rand()*32768) }' /dev/null)
  #echo "export PS1='\[\033[37;1m\][\[\033[35;1m\]\u\[\033[0m\]@\[\033[34;1m\]\h \[\033[37;1m\]➜ \[\033[31;1m\]\w \[\033[33;1m\]\t\[\033[37;1m\]]\[\033[32;1m\]\[\]\\$ \[\033[m\]'" >>/etc/bashrc
  echo "if [ \$(whoami) = "root" ]; then
    export PS1='\[\033[37;1m\][\[\033[31;1m\]\u\[\033[0m\]@\[\033[34;1m\]\h \[\033[37;1m\]➜ \[\033[31;1m\]\w \[\033[33;1m\]\t\[\033[37;1m\]]\[\033[32;1m\]\[\]\\$ \[\033[m\]'
else
    export PS1='\[\033[37;1m\][\[\033[35;1m\]\u\[\033[0m\]@\[\033[34;1m\]\h \[\033[37;1m\]➜ \[\033[31;1m\]\w \[\033[33;1m\]\t\[\033[37;1m\]]\[\033[32;1m\]\[\]\\$ \[\033[m\]'
fi" >>/etc/bashrc
  sed -i '$ a\set -o vi\nalias vi="vim"\nalias ll="ls -ahlF --color=auto --time-style=long-iso"\nalias ls="ls --color=auto --time-style=long-iso"\nalias grep="grep --color=auto"' /etc/bashrc
  success "bashrc alias 设置完成。\n"
}

# 配置vim
config_vim() {
  info "*** 开始配置vim ***"
  if ! grep pastetoggle /etc/vimrc >>/dev/null; then
    #[ $? -eq 0 ]; then
    sed -i '$ a\set pastetoggle=<F9>\nsyntax on\nset tabstop=4\nset softtabstop=4\nset shiftwidth=4\nset expandtab\nset bg=dark\nset ruler\ncolorscheme ron' /etc/vimrc
    success "vim 配置完成。\n"
  else
    warn "vim 已经配置, 进行下一步设置...\n"
    config_timezone
  fi
}

# 设置时区同步
config_timezone() {
  info "*** 设置系统时区和时间同步 ***"
  if ! timedatectl | grep "Asia/Shanghai"; then
    timedatectl set-local-rtc 0 && timedatectl set-timezone Asia/Shanghai
  else
    cont "系统当前时区为 Asia/Shanghai ..."
  fi
  #同步时间
  yum -y install ntpdate
  ntpdate -u cn.ntp.org.cn
  # 设置定时同步
  cont "每 ${BCyan}20${Color_off} 分钟进行一次时间同步..."
  echo "*/20 * * * * root /usr/sbin/ntpdate cn.ntp.org.cn" >>/etc/crontab
  systemctl reload crond
  #yum -y install chrony
  #sed -i '/server 3.centos.pool.ntp.org iburst/a\\server ntp1.aliyun.com iburst\nserver ntp2.aliyun.com iburst\nserver ntp3.aliyun.com iburst\nserver ntp4.aliyun.com iburst\nserver ntp5.aliyun.com iburst\nserver ntp6.aliyun.com iburst\nserver ntp7.aliyun.com iburst' /etc/chrony.conf
  #systemctl enable chronyd.service && systemctl start chronyd.service
  success "系统时区和时间同步设置完成。\n"
}

# 配置 ulimit
config_ulimit() {
  info "*** 配置 ulimit***"
  if [ ! -z "$(grep ^ulimit /etc/rc.local)" -a "$(grep ^ulimit /etc/rc.local | awk '{print $3}' | head -1)" != '655360' ]; then
    sed -i 's/^ulimit.*/ulimit -SHn 655360/g' /etc/rc.local
  else
    sed -i '$ a\ulimit -SHn 655360' /etc/rc.local
  fi
  cat >/etc/security/limits.conf <<EOF
* soft nproc 102400
* hard nproc 102400
* soft nofile 102400
* hard nofile 102400
EOF
  ulimit -n 102400
  success "Ulimit 配置完成。\n"
}

# 禁用 selinux
config_selinux() {
  info "*** 禁用 selinux ***"
  SELINUX=$(grep -c SELINUX=disabled /etc/selinux/config)
  if [ "$SELINUX" -eq 1 ]; then
    success "selinux 已禁用"
  else
    setenforce 0
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    success "禁用 selinux 完成。\n"
  fi
}

# 配置 firewall
config_firewall() {
  info "*** 配置 firewalld 防火墙 ***"
  if ! rpm -qa | grep firewalld >>/dev/null; then
    warn "没有安装 firewalld\n"
  else
    systemctl enable firewalld && systemctl start firewalld
    cont "放通 SSH ${BYellow}$ssh_port${Color_off} 端口..."
    firewall-cmd --permanent --add-port="$ssh_port"/tcp
    # 开启 NAT 转发 默认关闭
    #firewall-cmd --permanent --add-masquerade
    firewall-cmd --rel && firewall-cmd --list-all
    success "防火墙配置完成。\n"
  fi
}

# 配置sysctl
config_sysctl() {
  info "*** 优化 sysctl 配置 ***"
  cp -f /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%F)-$(awk 'BEGIN { srand(); print int(rand()*32768) }' /dev/null)
  cat /dev/null >/etc/sysctl.conf
  cat >/etc/sysctl.conf <<EOF
fs.file-max = 655350
fs.suid_dumpable = 0
vm.swappiness = 0
vm.dirty_ratio = 20
# overcommit_memory 内存机制
vm.overcommit_memory=1
vm.dirty_background_ratio = 5
# 开启重用。允许将TIME-WAIT sockets 重新用于新的TCP 连接
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
# 开启SYN洪水攻击保护
net.ipv4.tcp_syncookies = 1
# 当keepalive 起用的时候, TCP 发送keepalive 消息的频度。缺省是2 小时
net.ipv4.tcp_keepalive_time = 600
# timewait的数量, 默认18000
net.ipv4.tcp_max_tw_buckets = 36000
net.core.somaxconn = 262144
net.core.netdev_max_backlog = 262144
net.ipv4.tcp_max_orphans = 262144
net.netfilter.nf_conntrack_max = 25000000
net.netfilter.nf_conntrack_tcp_timeout_established = 180
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
# 开启反向路径过滤(增强网络安全)
net.ipv4.conf.all.rp_filter = 1
# IP 转发, 默认关闭
#net.ipv4.ip_forward=1
EOF
  /usr/sbin/sysctl -p
  success "sysctl 优化完成。\n"
}

# 禁用IPv6
disable_ipv6() {
  info "*** 禁用IPv6 ***"
  cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%F)-$(awk 'BEGIN { srand(); print int(rand()*32768) }' /dev/null)
  sed -i '$a\net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf
  sed -i '$a\NETWORKING_IPV6=no' /etc/sysconfig/network
  sed -i '/^#AddressFamily/s/#AddressFamily any/AddressFamily inet/g' /etc/ssh/sshd_config
  systemctl restart sshd
  success "IPv6禁用完成。\n"
}

# 设置IP地址
config_ipadd() {
  # 获取网卡信息
  # 网卡名称
  NIC=$(ifconfig | awk '{print $1}' | cut -f1 -d ":" | awk 'NR==1 {print $1}')
  # IP地址
  #ipadd=$(ifconfig eth0 | awk '/inet/ {print $2}' | cut -f2 -d ":" | awk 'NR==1 {print $1}')
  #ipadd=$(ifconfig | awk '{print $2}' | awk 'NR==2 {print $1}')
  ipadd=$(ip addr | awk '/^[0-9]+: / {}; /inet.*global/ {print gensub(/(.*)\/(.*)/, "\\1", "g", $2)}')
  #网关地址
  gateway=$(netstat -rn | awk '{print $2}' | awk 'NR==3 {print $1}')
  # 子网掩码
  #netmask=$(ifconfig eth0 | awk '/inet/ {print $4}' | cut -f2 -d ":" | awk 'NR==1 {print $1}')
  netmask=$(ifconfig | awk '{print $4}' | awk 'NR==2 {print $1}')
  #DNS1
  dns1=$(grep nameserver /etc/resolv.conf | awk 'NR==1 {print $2}')
  #DNS2
  dns2=$(grep nameserver /etc/resolv.conf | awk 'NR==2 {print $2}')
  info "*** 配置 IP 地址 ***"
  printf "当前网卡名称为: %s\n" "$NIC"
  printf "输入IP地址 (留空默认: %s): " "$ipadd"
  read -r IP_ADD
  printf "输入网关地址 (留空默认: %s): " "$gateway"
  read -r GATEWAY
  printf "输入子网掩码 (留空默认: %s): " "$netmask"
  read -r NETMASK
  printf "输入主要DNS服务器 (留空默认: %s): " "$dns1"
  read -r DNS1
  printf "输入辅助DNS服务器 (留空默认: %s): " "$dns2"
  read -r DNS2
  sed -i 's/BOOTPROTO=.*/BOOTPROTO="static"/g' /etc/sysconfig/network-scripts/ifcfg-"$NIC"

  if [ "$IP_ADD" = '' ]; then
    sed -i '$ a\IPADDR='"$ipadd"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  else
    sed -i '$ a\IPADDR='"$IP_ADD"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  fi
  if [ "$GATEWAY" = '' ]; then
    sed -i '$ a\GATEWAY='"$gateway"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  else
    sed -i '$ a\GATEWAY='"$GATEWAY"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  fi
  if [ "$NETMASK" = '' ]; then
    sed -i '$ a\NETMASK='"$netmask"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  else
    sed -i '$ a\NETMASK='"$NETMASK"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  fi
  if [ "$DNS1" = '' ]; then
    sed -i '$ a\DNS1='"$dns1"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  else
    sed -i '$ a\DNS1='"$DNS1"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  fi
  if [ "$DNS2" = '' ]; then
    sed -i '$ a\DNS2='"$dns2"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  else
    sed -i '$ a\DNS2='"$DNS2"'' /etc/sysconfig/network-scripts/ifcfg-"$NIC"
  fi
  success "IP地址设置完成。\n"
}

install_nginx() {
  info "*** 安装 Nginx ***"
  # 安装nginx
  yum install -y nginx
  systemctl enable nginx
  cont "Firewalld 防火墙放通 http & https 端口..."
  while :; do
    printf "请输入 http 端口(留空默认: 80): "
    read -r http_port
    if [ "$http_port" = "" ]; then
      http_port="80"
    fi
    if [[ ! $http_port =~ ^[0-9]+$ ]]; then
      warn "端口仅支持${Red}数字${Color_off}, 请重新输入!\n"
    elif [ "$http_port" -gt "65535" ]; then
      warn "端口号不能超过 ${Red}65535${Color_off}, 请重新输入!\n"
    else
      break
    fi
  done
  while :; do
    printf "请输入 https 端口(留空默认: 443): "
    read -r https_port
    if [ "$https_port" = "" ]; then
      https_port="443"
    fi
    if [[ ! $https_port =~ ^[0-9]+$ ]]; then
      warn "端口仅支持${Red}数字${Color_off}, 请重新输入!\n"
    elif [ "$https_port" -gt "65535" ]; then
      warn "端口号不能超过 ${Red}65535${Color_off}, 请重新输入!\n"
    else
      break
    fi
  done
  firewall-cmd --permanent --add-port=$http_port/tcp
  firewall-cmd --permanent --add-port=$https_port/tcp
  firewall-cmd --rel
  nginx_version=$(nginx -v 2>&1 | grep "nginx" | cut -f2 -d "/")
  if ! systemctl start nginx; then
    warn "Nginx 启动失败，请查看配置!"
  else
    success "Nginx 安装启动完成。\n"
  fi
}

other() {
  yum clean all
  rm -rf /var/cache/yum/*
}

main() {
  welcome
  #config_nameserver
  system_update
  install_tools
  delete_useless_user
  disable_services
  root_sshkey
  create_user
  config_sshd
  config_bashrc
  config_vim
  config_timezone
  disable_ipv6
  #config_ipadd
  config_ulimit
  config_selinux
  config_firewall
  config_sysctl
  install_nginx
  other
}
main

# 初始化计时结束
endTime=$(date +%Y%m%d-%H:%M)
endTime_s=$(date +%s)
# 计算用时分钟 $startTime ---> $endTime
sumTime=$((($endTime_s - $startTime_s) / 60))
# 内网IP地址
local_ipadd=$(ip addr | awk '/^[0-9]+: / {}; /inet.*global/ {print gensub(/(.*)\/(.*)/, "\\1", "g", $2)}')
msg "\n${Cyan}系统初始化用时: ${BPurple}$sumTime${Color_off}${Cyan} 分钟${Color_off}${Cyan}
 +------------------------------------------------------------------------+
 |             ${Green}系统初始化完成，请保存好以下信息并执行重启系统!${Cyan}            |
 +------------------------------------------------------------------------+${Color_off}\n"
# 判断 go 是否存在
if [ -f "/usr/bin/go" ]; then
  msg "${White}go 版本: ${BCyan}$go_version${Color_off}"
else
  printf ''
fi
# 判断 git 是否存在
if [ -f "/usr/bin/git" ]; then
  msg "${White}git 版本: ${BCyan}$git_version${Color_off}"
else
  printf ''
fi
msg "${Blue}================================
${Green}SSH 端口: ${Yellow}$ssh_port
${Green}IP地址: ${Yellow}$MYIP
${Green}用户名: ${Purple}$user_name
${Green}密码: ${Red}$user_passwd
${Blue}请牢记您的密码!!!
*** 系统默认${Red}禁止${Blue}密码登陆, 需要密码登陆请使用以下命令设置: ${White}
sed -i '/^PasswordAuthentication no/s/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
systemctl restart sshd
${Blue}================================${Color_off}
${Green}内网连接: ${Yellow}ssh -p $ssh_port -i ~/.ssh/私钥文件 $user_name@$local_ipadd${Color_off}
${Green}互联网连接: ${Yellow}ssh -p $ssh_port -i ~/.ssh/私钥文件 $user_name@$MYIP${Color_off}"
# 清除历史记录
cat /dev/null > ~/.bash_history && history -c
# 判断 nginx 是否存在
if [ -f "/usr/sbin/nginx" ]; then
  msg "${Blue}================================\n${White}nginx 版本: ${BCyan}$nginx_version${Color_off}\n${White}nginx http 端口: ${BYellow}$http_port${Color_off}\n${White}nginx https 端口: ${BYellow}$https_port${Color_off}"
else
  printf ''
fi
cat /dev/null >~/.bash_history && history -cw
printf "\n\nXray服务器系统环境初始化完毕, 是否立即重启服务器?[y/n]"
read -p ": " is_reboot
while [[ ! $is_reboot =~ ^[y,n]$ ]]; do
  warn "输入有误, 只能输入[y/n]"
  read -p "[y/n]: " is_reboot
done
if [ "$is_reboot" = 'y' ]; then
  reboot
fi
