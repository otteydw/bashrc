# .bashrc
# Daniel W. Ottey

# Source global definitions
[ -f /etc/bashrc ] && . /etc/bashrc

# Define some colors first:
#NC='\e[0m'              # No Color
BLACK='\e[0;30m'
DARK_GRAY='\e[1;30m'
BLUE='\e[0;34m'
LIGHT_BLUE='\e[1;34m'
GREEN='\e[0;32m'
LIGHT_GREEN='\e[1;32m'
CYAN='\e[0;36m'
LIGHT_CYAN='\e[1;36m'
RED='\e[0;31m'
LIGHT_RED='\e[1;31m'
PURPLE='\e[0;35m'
LIGHT_PURPLE='\e[1;35m'
BROWN='\e[0;33m'
YELLOW='\e[1;33m'
LIGHT_GRAY='\e[0;37m'
WHITE='\e[1;37m'
DEFAULT_COLOR='\e[0m'

# Determine hostnamme
if [ -f /etc/release ]; then
  grep "Solaris" /etc/release >/dev/null 2>&1 && MY_OS="SunOS"
	[ "${MY_OS}" = "SunOS" ] && MY_HOSTNAME=`cat /etc/nodename` || MY_HOSTNAME="unknown"
else
	MY_HOSTNAME=`hostname -s 2>/dev/null` || MY_HOSTNAME=`hostname` || MY_HOSTNAME="unknown"
  FQDN=`hostname`
fi

# Determine if we're using CYGWIN
uname | grep -q "CYGWIN" && MY_OS="CYGWIN"

# Try to determine datacenter name based on format of FQDN...  SERVERNAME.DATACENTER.DOMAIN.TLD
PERIOD_COUNT=`echo ${FQDN} | tr -d -c '.\n' | awk '{ print length; }'`
if [ ${PERIOD_COUNT} -eq 3 ]; then
  DATACENTER=`echo ${FQDN} | awk -F. {'print $2'} | tr [:lower:] [:upper:]`
fi
PERIOD_COUNT=

echo ${FQDN} | grep -q ".home$" && DATACENTER="Home"

# Set email address based on the datacenter.  Default to work email.
case ${DATACENTER} in
  "Home" )
    EMAIL_ADDRESS="dan@bluefrogs.us"
  ;;
  * )
    EMAIL_ADDRESS="dan_ottey@dell.com"
	;;
esac

if [ "${MY_OS}" = "SunOS" ]; then
  if [ -t 0 ]; then
    export TERM=vt220
    PS1="[\$(date +%H%M%Z)]\[${LIGHT_RED}\][SunOS]\[${LIGHT_CYAN}\][\u\[${YELLOW}\]@\h:\[${LIGHT_PURPLE}\]\w]\[${WHITE}\]$\[${WHITE}\]"
    /usr/bin/stty columns 120
    /usr/bin/stty erase ^H
    #return
  fi
else
  if [ -e /usr/share/terminfo/x/xterm-256color ]; then
    export TERM='xterm-256color'
  elif [ -e /usr/share/terminfo/x/xterm ]; then
    export TERM='xterm'
  else
    export TERM='linux'
  fi

  if [ "${MY_OS}" = "CYGWIN" ]; then
    if [ -e ${HOME}/.ssh/config ]; then
      alias ssh="ssh -F ${HOME}/.ssh/config"
      alias scp="scp -F ${HOME}/.ssh/config"
    fi
    NOTEPAD="/c/Program Files//Notepad++/notepad++.exe"
    if [ -x "${NOTEPAD}" ]; then
      alias notepad="${NOTEPAD}"
      alias vi="${NOTEPAD}"
    fi
    [ -x /cygdrive/c/Windows/system32/ping ] && alias ping="/cygdrive/c/Windows/system32/ping"
    alias goog="lynx -auth=dan_ottey www.google.com"
    alias iplist='ipconfig | grep --color=never Address'
    [ -d /cygdrive/c/cmdline ] && export PATH="/cygdrive/c/cmdline:${PATH}"
    # Launch "Active Directory Users and Computers"
    alias labdsa='runas /user:dottey@LAB "mmc ${WINDIR}\system32\dsa.msc"'
    alias ifconfig='ipconfig'
    alias df='df -kTH'
    #alias network_reset="ipconfig /release; ipconfig /renew"
    #alias wireless="ipconfig /release *LAN*"
    #alias lan="ipconfig /release *Wireless*"
    [ -e /c/downloads ] && alias downloads="cd /c/downloads"
    alias cls='echo -e -n "\E[2J"'
    /usr/bin/which clear >/dev/null 2>&1 || alias clear='cls'
    alias red="netsh wlan connect name=red"
    alias east="netsh wlan connect name=east"
    alias slack_kill="powershell kill -n slack"
  fi

  if [ "${MY_OS}" = "CYGWIN" ]; then
    #PS1="[\$(date +%H%M%Z)]\[${LIGHT_RED}\][Cygwin]\[${LIGHT_CYAN}\][\u\[${YELLOW}\]@\h:\[${LIGHT_PURPLE}\]\w]\[${WHITE}\]$\[${WHITE}\]"
    PS_FILLER="Cygwin"
  elif [ "a${DATACENTER}" != "a" ]; then
    PS_FILLER="${DATACENTER}"
  else
    #if [ `hostname | tr -d -c '.' | awk '{ print length; }'` -gt 1 ]; then
    # First 3 letters of hostname
    #PS_FILLER=`echo ${MY_HOSTNAME} | cut -c -3 | tr [:lower:] [:upper:]`
    PS_FILLER="${DATACENTER}"
  fi

  PS1="[\$(date +%H%M%Z)]\[${LIGHT_RED}\][${PS_FILLER}]\[${LIGHT_CYAN}\][\u\[${YELLOW}\]@\h:\[${LIGHT_PURPLE}\]\w]\[${WHITE}\]$\[${WHITE}\]"
fi

# User specific aliases and functions
alias l='ls -lih'
alias which='type -all'
alias path='echo -e ${PATH//:/\\n}'
alias du='du -kh'
alias lower='tr [:upper:] [:lower:]'
alias upper='tr [:lower:] [:upper:]'
alias pass_sort='sort -t: -k3 -n /etc/passwd'
alias nmap_verbose='sudo nmap -sS -O -v -A -p1-65535 -T5'
alias hogs="ps -eo pcpu,pid,user,args | sort -r -k1 | less"
alias pidinfo="sudo /bin/ps -o pid,lstart,command -p"

# Assist in common typos
alias Grep='grep'
alias GRep='grep'
alias GREp='grep'
alias GREP='grep'

# The 'ls' family (this assumes you use the GNU ls)
[ "$MY_OS" = "SunOS" ] || alias ls='ls -hF --color'       # add colors for filetype recognition
alias la='ls -Al'               # show hidden files
alias lx='ls -lXB'              # sort by extension
alias lk='ls -lSr'              # sort by size
alias lc='ls -lcr'              # sort by change time
alias lu='ls -lur'              # sort by access time
alias lr='ls -lR'               # recursive ls
alias lt='ls -ltr'              # sort by date
alias lm='ls -al |more'         # pipe through 'more'
alias tree='tree -Csu'          # nice alternative to 'ls'
export LS_COLORS='no=00:fi=00:di=00;33:ln=01;36:pi=40;33:so=01;35:bd=40;33;01:cd=40;33;01:or=01;05;37;41:mi=01;05;37;41:ex=01;32:*.cmd=01;32:*.exe=01;32:*.com=01;32:*.btm=01;32:*.bat=01;32:*.sh=01;32:*.csh=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.gz=01;31:*.bz2=01;31:*.bz=01;31:*.tz=01;31:*.rpm=01;31:*.cpio=01;31:*.jpg=01;35:*.gif=01;35:*.bmp=01;35:*.xbm=01;35:*.xpm=01;35:*.png=01;35:*.tif=01;35:'

# These are aliases just because they're executable only by root and won't tab complete
alias useradd='/usr/sbin/useradd'
alias usermod='/usr/sbin/usermod'
alias userdel='/usr/sbin/userdel'

# tailoring 'less'
alias less='less -IX'
alias more='less -IX'
which most >/dev/null 2>&1 && {
  export PAGER="most"
} || {
  export PAGER='less -IX'
}

# Aliases for the ssh agent
agt () {
	eval `ssh-agent`
}

alias keyon="ssh-add -t 10800"
alias keyoff='ssh-add -D'
alias keylist='ssh-add -l'

alias rescan='echo "- - -" | sudo tee /sys/class/scsi_host/host*/scan'

function getwwn () {
  for host in `/bin/ls /sys/class/scsi_host`;
  do
    if [ -e /sys/class/scsi_host/${host}/node_name ]; then
      NODE_NAME="`cat /sys/class/scsi_host/${host}/node_name`"
    elif [ -e /sys/class/fc_host/${host}/node_name ]; then
      NODE_NAME="`cat /sys/class/fc_host/${host}/node_name`"
    elif [ -e /sys/class/scsi_host/${host}/lpfc_symbolic_name ]; then
      NODE_NAME="`cat /sys/class/scsi_host/${host}/lpfc_symbolic_name | sed -e 's|Emulex PPN-||'`"
    else
      NODE_NAME=""
    fi
    NODE_NAME=`echo ${NODE_NAME} | upper`
    [ -e /sys/class/scsi_host/${host}/modeldesc ] && MODELDESC="     $(cat /sys/class/scsi_host/${host}/modeldesc)" || MODELDESC=""
    TEXT="${NODE_NAME}${MODELDESC}"
    [ -n "${TEXT}" ] && echo "${TEXT}"
  done
}

# tailoing vi
if [ -x /usr/bin/vim ]; then
  alias vi='/usr/bin/vim'
  export EDITOR="/usr/bin/vim"
elif [ -x /bin/vi ]; then
  export EDITOR="/bin/vi"
elif [ -x /usr/bin/vi ]; then
  export EDITOR="/usr/bin/vi"
fi

function random_password () {
  COUNT=$1
  [ -z "$COUNT" ] && COUNT=16
  command -v pwgen >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    pwgen -sy -N1 ${COUNT}
  else
    PASSWORD=`cat /dev/urandom | tr -cd \!\@\#a-zA-Z0-9 | fold -w${COUNT} | head -n 1`
    echo $PASSWORD
  fi
}

function random_text_password () {
  COUNT=$1
  [ -z "$COUNT" ] && COUNT=16
  command -v pwgen >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    pwgen -s -N1 ${COUNT}
  else
    echo "Please install pwgen!"
    return 1
  fi
}

datestamp () {
  echo $(date +%Y%m%d-%H%M)
}

datestampss () {
  echo $(date +%Y%m%d-%H%M%S)
}

hoststamp () {
  echo "$(date +%Y%m%d-%H%M)-$(hostname -s)"
}

hoststampss () {
  echo "$(date +%Y%m%d-%H%M%S)-$(hostname -s)"
}

# Source a local bashrc if one exists.
[ -e ${HOME}/.bashrc.local ] && source ${HOME}/.bashrc.local
