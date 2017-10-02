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
alias xterm="xterm -bg black -fg green -cr purple +cm +dc -geometry 80x20+100+50"
alias iowait="ps ax | awk '\$3 ~ /^D/ { print \$0 }'"
alias splunk_tail_status="curl -u admin -k https://localhost:8089/services/admin/inputstatus/TailingProcessor:FileStatus"
alias rot13="tr '[A-Za-z]' '[N-ZA-Mn-za-m]'"
alias numeric_permissions="stat -c '%a %n'"
alias partition="echo '1,,' | sudo sfdisk -uM "
alias cputest='openssl speed -multi'
alias miu='/bin/ps -eo rss | awk '\''{SUM += $1} END {print SUM/1024 " - Mebibytes in Memory Used"}'\'''
#alias auto_emcgrab="cd ~/emcgrab; sudo ./emcgrab.sh -legal -autoexec"

# Boomi-specific aliases
[ -x /usr/local/scripts/atomview.sh ] && alias atomview="sudo watch -n5 /usr/local/scripts/atomview.sh"
alias container_count='ps aux | grep java | grep boomi | grep Container | grep -c -v grep'
alias atomprocess_count='ps aux | grep java | grep boomi | grep -v Container | grep -c -v grep'


# Elasticsearch aliases
alias es_cluster_health="curl -XGET 'http://localhost:9200/_cluster/health?pretty' 2>/dev/null"
alias es_cluster_status="curl -XGET 'http://localhost:9200/_cluster/health?pretty' 2>/dev/null | grep 'status' | sed -e 's|\"||g' -e 's|,||g' | awk -F': ' {'print \$2'}"

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
if ! [ -f /etc/debian_version ]; then
  alias less='less -IX'
  alias more='less -IX'
fi
which most >/dev/null 2>&1 && {
  export PAGER="most"
} || {
  export PAGER='less -IX'
}

# These are Linux-only
if [ "${MY_OS}" != "SunOS" ]; then

  if [ -e /etc/redhat-release ]; then
    grep -q "^Red Hat Linux Advanced Server release 2" /etc/redhat-release 2>/dev/null && export MY_OS="RHEL2"
    grep -q "^Red Hat Enterprise Linux Server release 5" /etc/redhat-release 2>/dev/null && export MY_OS="RHEL5"
    grep -q "^Red Hat Enterprise Linux Server release 6" /etc/redhat-release 2>/dev/null && export MY_OS="RHEL6"
    grep -q "^Red Hat Enterprise Linux Server release 7" /etc/redhat-release 2>/dev/null && export MY_OS="RHEL7"
    grep -q "^Fedora" /etc/redhat-release 2>/dev/null && export MY_OS="FEDORA"
  elif [ -e /frontview ]; then
    MY_OS="ReadyNAS"
  fi

	if [ "a${MY_OS}" = "a" ]; then
    MY_OS="OS_UNKNOWN"
  fi

	#[ "$MY_OS" != "RHEL2" ] && export GREP_OPTIONS="--color"
	# GREP_OPTIONS is deprecated
  [ "${MY_OS}" != "RHEL2" ] && [ "${MY_OS}" != "ReadyNAS" ] && alias grep="grep --color"

	alias rpmq='rpm -q --qf "%{NAME}-%{VERSION}-%{RELEASE} (%{ARCH})\n"'

	rpm-extract () {
    RPM=$1
    /usr/bin/rpm2cpio $RPM | cpio -idmv
	}

	alias ipcalc="ipcalc -n"
  #echo "MY_OS=${MY_OS}"
	if [ "{$MY_OS}" != "CYGWIN" ]; then
    [ -x /sbin/ip ] && alias iplist='/sbin/ip addr list | /bin/grep "inet "' || alias iplist='/sbin/ifconfig -a | /bin/grep "inet "'
  fi

	swap_percent() {
    SWAP_LINE=`free | grep "^Swap"`
    SWAP_USED=`echo ${SWAP_LINE} | awk {'print $3'}`
    SWAP_TOTAL=`echo ${SWAP_LINE} | awk {'print $2'}`
    AWKSCRIPT=' { printf( "%3.2f\n", $1*100/$2 ) }'
    SWAP_PERCENT=`echo ${SWAP_USED} ${SWAP_TOTAL} | awk "${AWKSCRIPT}"`
    echo "Swap is ${SWAP_PERCENT}% full."
  }

	tty | grep -qe "tty" && ON_TTY=0 || ON_TTY=1

	if [ ${ON_TTY} -eq 0 ]; then
    # On TTY
    export TERM=linux
    export GREP_COLOR=32
  else
    # On PTS
    [ -t 0 ] && ps | grep 'bash' | awk {'print $2'} | grep 'pts' >/dev/null 2>&1
    if [ $? -eq 0 ]; then
      # Strip 6 beginning digits for Boomi servers at Rackspace
      MY_TITLE_NAME=`echo ${MY_HOSTNAME} | sed -e "s|^[[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]][[:digit:]]-||g"`
      export PROMPT_COMMAND='echo -ne "\033]2;${MY_TITLE_NAME}\007\033]1;${MY_TITLE_NAME}\007"'
    fi
    export GREP_COLOR='00;38;5;157'
	fi

	# Bash shell options and completions. (They just make life nicer)
	shopt -s extglob        # necessary
	shopt -s cdspell
	shopt -s cdable_vars
	shopt -s checkhash
	shopt -s checkwinsize
	shopt -s mailwarn
	shopt -s sourcepath
	shopt -s cmdhist
	shopt -s histappend histreedit histverify

	set +o nounset          # otherwise some completions will fail

	complete -A hostname   rsh rcp telnet rlogin r ftp ping disk
	complete -A export     printenv
	complete -A variable   export local readonly unset
	complete -A enabled    builtin
	complete -A alias      alias unalias
	complete -A function   function
	complete -A user       su mail finger

	complete -A helptopic  help     # currently same as builtins
	complete -A shopt      shopt
	complete -A stopped -P '%' bg
	complete -A job -P '%'     fg jobs disown

	complete -A directory  mkdir rmdir
	complete -A directory   -o default cd

	# Compression
	complete -f -o default -X '*.+(zip|ZIP)'  zip
	complete -f -o default -X '!*.+(zip|ZIP)' unzip
	complete -f -o default -X '*.+(z|Z)'      compress
	complete -f -o default -X '!*.+(z|Z)'     uncompress
	complete -f -o default -X '*.+(gz|GZ)'    gzip
	complete -f -o default -X '!*.+(gz|GZ)'   gunzip
	complete -f -o default -X '*.+(bz2|BZ2)'  bzip2
	complete -f -o default -X '!*.+(bz2|BZ2)' bunzip2

	# Postscript,pdf,dvi.....
	complete -f -o default -X '!*.ps'           gs ghostview ps2pdf ps2ascii
	complete -f -o default -X '!*.dvi'          dvips dvipdf xdvi dviselect dvitype
	complete -f -o default -X '!*.pdf'          acroread pdf2ps
	complete -f -o default -X '!*.+(pdf|ps)'    gv
	complete -f -o default -X '!*.texi*'        makeinfo texi2dvi texi2html texi2pdf
	complete -f -o default -X '!*.tex'          tex latex slitex
	complete -f -o default -X '!*.lyx'          lyx
	complete -f -o default -X '!*.+(htm*|HTM*)' lynx html2ps
	# Multimedia
	complete -f -o default -X '!*.+(jp*g|gif|xpm|png|bmp)' xv gimp
	complete -f -o default -X '!*.+(mp3|MP3)'              mpg123 mpg321
	complete -f -o default -X '!*.+(ogg|OGG)'              ogg123
	complete -f -o default -X '!*.pl'                      perl perl5

	# Enable tab complete for sudo commands
	complete -cf sudo

	# -> Prevents accidentally clobbering files.
	alias rm='rm -iv'
	alias cp='cp -iv'
	alias mv='mv -iv'

  alias rpmreport='rpm -qa | sort | xargs rpm -q --qf "%{NAME}-%{VERSION}-%{RELEASE} \| %{ARCH} \| %{VENDOR} \| %{INSTALLTIME:date} \n"'
  alias rpm_name_and_arch='rpm -qa | xargs rpm -q --qf "%{NAME}\.%{ARCH} \n" | sort -u'
  alias get_serial_number='sudo /usr/sbin/dmidecode -s system-serial-number'

  if [ "${MY_OS}" = "RHEL5" ]; then
    alias mydstat='dstat -tclmdy -N total -M topio --noupdate 5'
  else
    alias mydstat='dstat -tclmdy -N total -M topio --socket --noupdate 5'
  fi

  function hardware_model ()
  {
    MANUFACTURER=`sudo dmidecode -s system-manufacturer`
    PRODUCT=`sudo dmidecode -s system-product-name`
    echo "${MANUFACTURER} ${PRODUCT}"
  }

fi

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

send_file_by_email () {
  EMAIL_ADDRESS=$1
  [ -x /usr/bin/mutt ] || ( echo "Mutt must be installed."; exit 1)
  FILE=$2
  [ -z "${FILE}" ] && ( echo "You must enter a filename to send."; exit 1 )
  [ -e "${FILE}" ] || ( echo "${FILE} does not exist."; exit 1 )
  [ -x /usr/bin/mutt ] || ( echo "/usr/bin/mutt does exist or is not executable."; exit 1 )
  /usr/bin/mutt -s "${FILE}" -a "${FILE}" -- ${EMAIL_ADDRESS} < /dev/null
}

alias email_me="send_file_by_email ${EMAIL_ADDRESS} $2"

function colortable () {
  # prints a color table of 8bg * 8fg * 2 states (regular/bold)
  echo
  echo Table for 16-color terminal escape sequences.
  echo Replace ESC with \\033 in bash.
  echo
  echo "Background | Foreground colors"
  echo "---------------------------------------------------------------------"
  for((bg=40;bg<=47;bg++)); do
    for((bold=0;bold<=1;bold++)) do
      echo -en "\033[0m"" ESC[${bg}m   | "
      for((fg=30;fg<=37;fg++)); do
        if [ $bold == "0" ]; then
          echo -en "\033[${bg}m\033[${fg}m [${fg}m  "
        else
          echo -en "\033[${bg}m\033[1;${fg}m [1;${fg}m"
        fi
      done
      echo -e "\033[0m"
    done
    echo "--------------------------------------------------------------------- "
  done
  echo
  echo
}

alias colors=colortable

alias certfileinspect='openssl x509 -text -noout -in'
complete -f -o default -X '!*.crt' certfileinspect

function certurldownload {
  # $1 should be in form www.domain.com:443
  SERVERNAME=$(echo $1 | awk -F: {'print $1'})
  PORT=$(echo $1 | awk -F: {'print $2'})
  [ -z "${PORT}" ] && PORT="443"
  openssl s_client -showcerts -servername ${SERVERNAME} -connect ${SERVERNAME}:${PORT} </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
}

function certurlinspect {
  # $1 should be in form www.domain.com:443
  # Support SNI (-servername)
  certurldownload $1 | openssl x509 -text -noout
}

function csr_inspect {
  openssl req -in $1 -noout -text
}

function cert_verify {
  CA_BUNDLE=$1
  CERT=$2
  openssl verify -CAfile /etc/pki/tls/cert.pem -untrusted ${CA_BUNDLE} ${CERT}
}

function certftpinspect {
  openssl s_client -showcerts -connect $1 -starttls ftp </dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text -noout
}

function compare_key_and_cert ()
{
  KEY=$1
  CERT=$2
  KEY_SUM=`openssl rsa -noout -modulus -in ${KEY} | openssl md5`
  CERT_SUM=`openssl x509 -noout -modulus -in ${CERT} | openssl md5`
  openssl x509 -in ${CERT} -noout -subject -dates
  echo "${KEY} - ${KEY_SUM}"
  echo "${CERT} - ${CERT_SUM}"
  if [ "${KEY_SUM}" = "${CERT_SUM}" ]; then
    echo "Match!"
    return 0
  else
    echo "Mismatch!"
    return 1
  fi
}

# Function to remove comments from a file. (expects a file name as input)
function remove_comments () {
  grep -v '^#' $1 | grep -v '^$'
}

function connections () {
  netstat -an | awk '/tcp/ {print $6}' | sort | uniq -c
}

function psinfo () {
  pidinfo `pidof $1`
}

function evenodd () {
  # determine odd/even status by last digit
  LAST_DIGIT=`echo $1 | sed 's/\(.*\)\(.\)$/\2/'`
  case ${LAST_DIGIT} in
  0|2|4|6|8)
    return 1
    ;;
  *)
    return 0
    ;;
  esac
}

function isalive () {
  NODE=$1
  /bin/ping -c 1 ${NODE} >/dev/null 2>&1 && return 0 || return 1
}

function sslthing () {
  ossl=/usr/bin/openssl
  tempfile=/tmp/sslthing.tmp

	## Make a request (may be altered)
  echo "GET / HTTP/1.0" > $tempfile

	###### END OF CONFIGURATION #####

	if ! [ $1 ]; then
    echo syntax: $0 host:sslport [-v]
    exit
  fi

	if ! [ -e $ossl ]; then
	  echo The path to openssl is wrong, please edit $0
	  exit
	fi

	## Request available ciphers from openssl and test them
	for ssl in -ssl3 -tls1 -tls1_2
	do
	  echo
	  echo Testing `echo $ssl | cut -c2- | tr "a-z" "A-Z"`...
	  $ossl ciphers $ssl -v | while read line
	  do
	    cipher=`echo $line | awk '{print $1}'`
	    bits=`echo $line | awk '{print $5}' | cut -f2 -d\( | cut -f1 -d\)`
      if [ $2 ]; then
        echo -n $cipher - $bits bits...
      fi

	    if ($ossl s_client $ssl -cipher $cipher -connect $1 < $tempfile 2>&1 | grep ^New > /dev/null); then
	      if [ $2 ]; then
          echo OK
	      else
          echo $cipher - $bits bits
	      fi
      else
        if [ $2 ]; then
          echo Failed
        fi
      fi
    done | grep -v error
  done
}

function open_files_per_pid () {
  for PID in `ps -ef | awk '{print $2}' | grep -v PID`
  do
    /bin/echo -en "${PID}  "
    sudo lsof -p $PID | wc -l
  done
}

function lun_sort ()
{
  INQ="/usr/local/sbin/inq.LinuxAMD64"
  [ -x ${INQ} ] && sudo ${INQ} -showvol -nodots 2>/dev/null | grep emcpower | awk -F: {'print $1 $6 $7'} | sort -k2 || echo "${INQ} does not exist or is not executable."
}

function no-expire () {
  USER=$1
  sudo /usr/bin/chage -m 1 -M 99999 $USER
  sudo /usr/sbin/usermod -U $USER
}

# pause 'Press any key to continuu...'
function pause() {
  read -p "$*"
}

# Bash function to create a zeroed sparse file (expects a non negative integer as input)
function createsparsefile ()
{
  TIMESTAMP=`date +%Y%m%d%H%M%S`
  FILENAME=created_sparse_file_${TIMESTAMP}

  test $1 -ge 0 && dd if=/dev/zero of=${FILENAME} bs=1M count=0 seek=$1 || echo "Your input was not a numeric value greater than 0"
}

function calc ()
{
  awk "BEGIN{ print $* }" ;
}

function mean_max_min ()
{
  awk 'NR == 1 { max=$1; min=$1; sum=0 } { if ($1>max) max=$1; if ($1<min) min=$1; sum+=$1;} END {printf "Min: %f\tMax: %f\tAverage: %f\n", min, max, sum/NR}'
}

# One-liner web server using python
function websrv ()
{
  ( test $1 -gt 0 && test $1 -lt 65536 ) && python -m SimpleHTTPServer $1 || echo "Your input was not a port > 0 and < 65536"
}

function uri_escape()
{
  echo -E "$@" | sed 's/\\/\\\\/g;s/./&\n/g' | while read -r i; do echo $i | grep -q '[a-zA-Z0-9/.:?&=]' && echo -n "$i" || printf %%%x \'"$i"; done
}

function random_file()
{
  dd if=/dev/urandom of="${1}MBfile" bs=1M count=$1
}

function tzmulti ()
{
  TZ="US/Pacific" date
  TZ="US/Central" date
  TZ="US/Eastern" date
  TZ="UTC" date
  TZ="Europe/Berlin" date
}

function heapdump {
  PID=$1
  USERNAME="`ps --no-header -p ${PID} -o user`"
  if [[ $? -ne 0 ]]; then
    echo "PID ${PID} does not exist!"
    return 1
  fi
  STAMP="`date +%Y%m%d-%H%M%S`_`hostname -s`"
  DUMPFILE="${STAMP}-heap.bin"
  sudo su - ${USERNAME} -c "/usr/java/latest/bin/jmap -dump:format=b,file=${DUMPFILE} ${PID}" && echo "Heap dumped to ${DUMPFILE}" >&2 || echo "Problem during attempt to dump heap!" >&2
  #echo "Heap dumped to ${DUMPFILE}" >&2
}

function threaddump {
  PID=$1

  STAMP="`date +%Y%m%d-%H%M%S`_`hostname -s`"
  DUMPFILE="${STAMP}-threaddump.log"
  USERNAME="`ps --no-header -p ${PID} -o user`"
  if [[ $? -ne 0 ]]; then
    echo "PID ${PID} does not exist!"
    return 1
  fi
  sudo su - ${USERNAME} -c "/usr/java/latest/bin/jstack ${PID}" > ${DUMPFILE} && echo "Thread dump written to ${DUMPFILE}" >&2 || echo "Problem during attempt to dump threads!" >&2
  #echo "Thread dump written to ${DUMPFILE}" >&2
}

function atom-threaddump {
  PID=`/bin/ps --no-headers -o pid,cmd -C java | grep Container | awk {'print $1'}`
  threaddump $PID
}

function atom-heapdump {
  PID=`/bin/ps --no-headers -o pid,cmd -C java | grep Container | awk {'print $1'}`
  heapdump $PID
}

function plat-threaddump {
  PID=`/bin/ps --no-headers -o pid,cmd -C java | grep jetty | awk {'print $1'}`
  threaddump $PID
}

function plat-heapdump {
  PID=`/bin/ps --no-headers -o pid,cmd -C java | grep jetty | awk {'print $1'}`
  heapdump $PID
}

function atom-pause {
  PID=`/bin/ps --no-headers -o pid,cmd -C java | grep Container | awk {'print $1'}`
  USERNAME="`ps --no-header -p ${PID} -o user`"
  sudo su - ${USERNAME} -c "/usr/local/boomi/cloud/jmxutil/jmx_invoke.sh ${PID} com.boomi.container.services:type=ContainerController changeStatusAsync PAUSED_FOR_STOP"
}

function atomclouduptime {
  for NUM in `seq -w 1 14`; do SERVER="dfwatom${NUM}.dfw.boomi.com"; echo -en "${SERVER}\t";ssh ${SERVER} "uptime" 2>/dev/null; done
}

function labqaatomclouduptime {
  for NUM in `seq -w 1 12`; do SERVER="labqaatom${NUM}.lab.boomi.com"; echo -en "${SERVER}\t";ssh ${SERVER} "uptime" 2>/dev/null; done
}

function msepoch_to_date {
    MS=$1
    date -d @$(  echo "(${MS} + 500) / 1000" | bc)
}

function dmesg_with_human_timestamps () {
  $(type -P dmesg) "$@" | perl -w -e 'use strict;
    my ($uptime) = do { local @ARGV="/proc/uptime";<>}; ($uptime) = ($uptime =~ /^(\d+)\./);
    foreach my $line (<>) {
      printf( ($line=~/^\[\s*(\d+)\.\d+\](.+)/) ? ( "[%s]%s\n", scalar localtime(time - $uptime + $1), $2 ) : $line )
    }'
}

function datediff {
  firstdate=$1;
  secondate=$2;

  fullyear=$(date -d@$(( ( $(date -ud "$secondate" +'%s') - $(date -ud "$firstdate" +'%s') ) )) +'%Y years %m months %d days %H hours %M minutes %S seconds')
  yearsubtraction=$(( $(echo $fullyear | sed -r 's/^([0-9]+).*/\1/') - 1970 ))

  if [ $yearsubtraction -le '0' ]; then
    echo $fullyear | sed -r "s/^([0-9]+) years //"
  else
    echo $fullyear | sed -r "s/^([0-9]+) /$(printf %02d $yearsubtraction) /"
  fi
}

function driveclientkill {
  sudo kill -9 $(pidof driveclient)
}

function modtimerename ()
{
  OLDFILE=$1
  MODTIME=`stat ${OLDFILE} --format %y | awk -F. {'print $1'} | sed -e "s|\:|\.|g"`
  EXT=`echo ${OLDFILE} | awk -F . '{print $NF}'`
  NEWFILE="${MODTIME}.${EXT}"
  mv "${OLDFILE}" "${NEWFILE}"
}

# Display readable counts from postfix mailqueue
function mailcount ()
{
  qdir=`postconf -h queue_directory`
  incoming=`sudo find $qdir/incoming -type f -print | wc -l | awk '{print $1}'`
  activeonly=`sudo find $qdir/active -type f -print | wc -l | awk '{print $1}'`
  maildrop=`sudo find $qdir/maildrop -type f -print | wc -l | awk '{print $1}'`
  active=`sudo find $qdir/incoming $qdir/active $qdir/maildrop -type f -print | wc -l | awk '{print $1}'`
  defer=`sudo find $qdir/defer -type f -print | wc -l | awk '{print $1}'`
  deferred=`sudo find $qdir/deferred -type f -print | wc -l | awk '{print $1}'`
  printf "active: %d\ndefer: %d\ndeferred: %d\nincoming: %d\nactiveonly: %d\nmaildrop: %d\n" $active $defer $deferred $incoming $activeonly $maildrop
}

function db-report {
  CONNECT=$1
  STAMP="`date +%Y%m%d-%H%M%S`_`hostname -s`"
  REPORT="${STAMP}-db_report.txt"
  [ -f ~/.my.cnf ] || DO_SUDO="sudo"
  ${DO_SUDO} mysql ${CONNECT} -e "SELECT * FROM information_schema.innodb_locks\G; SELECT * FROM information_schema.innodb_trx\G; show engine innodb status\G; SHOW FULL PROCESSLIST\G;" > ${REPORT} && echo "Report written to ${REPORT}" >&2 || echo "Problem with running the report!" >&2
}

# Determine WAN IP based on available utilities.
if [ -x /usr/bin/wget ] || which wget > /dev/null 2>&1; then
  #alias wanip='wget -O - -q icanhazip.com'
  #alias wanip='wget -O - -q ifconfig.me/ip'
  alias wanip='wget -O - -q ipinfo.io/ip'
elif [ -x /usr/bin/curl ]; then
  #alias wanip='curl icanhazip.com'
  #alias wanip='curl ifconfig.me/ip'
  alias wanip='curl ipinfo.io/ip'
elif [ -x /usr/bin/dig ]; then
  alias wanip='dig +short myip.opendns.com @resolver1.opendns.com'
else
  alias wanip='echo "No available tool!"'
fi

export SSHOPTS="-XAC -t -o ConnectTimeout=30"

# Source a local bashrc if one exists.
[ -e ${HOME}/.bashrc.local ] && source ${HOME}/.bashrc.local

# Display uptime on login
#[ -e /usr/bin/uptime ] && echo && /usr/bin/uptime && echo
