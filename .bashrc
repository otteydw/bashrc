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

  PS1="[\$(date +%H%M%Z)]\[${LIGHT_RED}\][${PS_FILLER}]\[${LIGHT_CYAN}\][\u\[${YELLOW}\]@\h:\[${LIGHT_PURPLE}\]\w]\[${WHITE}\]$\[${WHITE}\]"
fi
