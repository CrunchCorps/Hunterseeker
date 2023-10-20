#!/usr/bin/env bash
#init

###################################################################
##/Coded/--/by/--/Bakeneko/--[10/2022]--/crunchCorps/--/JACURUTU/##
###################################################################

dirpath=$(pwd) #Current Location path.
VT=$(find . -name "vt" | head -n 1)
VTAPI=$(cat /home/$(echo ${SUDO_USER:-${USER}})/.vt.toml | cut -d"=" -f2 | cut -d"\"" -f2)

##### COLORS PALLETES #####
DGray='\033[38;5;244m' #Color Dark Gray
MGray='\033[1;38;5;247m' #Color Mid-Gray
Gray='\033[1;38;5;248m' #Color Gray
WGray='\033[38;5;253m' #Color White Gray
DGR='\033[0;32m' #Color DarkGreen.
LBlue='\033[1;34m' #Color Light Blue
LRed='\033[1;31m' #Color Light Red
LGreen='\033[1;32m' #Color Light Green
reset='\e[0m'

##### CHECK IF SCRIPT HAS PRIVILEGES #####
if ! [ $(stat HunterSeeker.sh | grep "Access: (" | cut -d '(' -f2 | cut -d '/' -f1) = 0777 ]; then
    echo -e "${DGR}"
    echo "The script need to be run as root." >&2
    exit 1
#    if ! [ $(id -u) = 0 ]; then
#        echo -e "${DGR}"
#        echo "The script need to be run as root." >&2
#        exit 1
#    fi
fi

#####TEST IF ROOT#####
if [ $SUDO_USER ]; 
    then
        real_user=$SUDO_USER
    else
        real_user=$(whoami)
fi

##### INSTALLIING PREQUISITES #####
###################################
##################
##### FIGLET #####
if ! command -v figlet &> /dev/null
then
  echo -e ${WGray}"figlet could not be found."
  echo -e "Installing."${MGray}
  sudo apt-get install figlet
  exit
fi
##################
##### TSHARK #####
if ! command -v tshark &> /dev/null
then
  echo -e ${WGray}"tshark could not be found."
  echo -e "Installing."${MGray}
  sudo apt-get install tshark
  exit
fi

#####SHORT HELP MENU#####
function HelpShort()
{
  clear
  tput setaf 196; figlet -f smslant Hunter-Seeker; tput sgr0
  echo -e "${WGray}[ Jacurutu | https://github.com/RandomLinoge ]" | sed 's/^/    /'
  echo -e -n "
  ${Gray}usage: ${MGray}Hunterseeker ${WGray}[-h] [-i] [-m FILENAME] [-b IP | ADDRESS] 
         [-o LOG OUTPUT DIRECTORY] [-v] [--live]

  ${LRed}Hunter-Seeker${MGray} is a tool used for basic analysis of URL links, IP addresses, 
  extracting and analysing suscpicous files and detect potential malware.

  options:
    -h                            Show this help message and exit.
   --help                         Show an extended help options and exit.
   --live                         Active Live-On Capture mode.
  
  "
  exit 1
}

#####FULL HELP MENU#####
function HelpFull()
{
  clear
  tput setaf 196; figlet -f slant Hunter-Seeker; tput sgr0
  echo -e "${WGray}[ Jacurutu | https://github.com/RandomLinoge ]" | sed 's/^/            /'
  echo -e -n "
  ${Gray}usage: ${MGray}Hunterseeker ${WGray}[-h] [-i] [-m FILENAME] [-b IP | ADDRESS] 
         [-o LOG OUTPUT DIRECTORY] [-v] [--live]

  ${LRed}Hunter-Seeker ${MGray}is a tool used for basic analysis of URL links, IP addresses, 
  extracting and analysing suscpicous files and detect potential malware.
  ${Gray}
  options:
  ${DGray}
    -i, --interactive             Interactive menus with questions.
    -m FILENAME                   List of servers and addresses to 
                                  attack, one entry per line, and 
                                  make some pwnsauce.
    -b IP, -b ADDRESS             Target an IP or a source address 
                                  to scan and detect for malicious
                                  sauce.
    -o DIRECTORY                  Directory to which log files will be
                                  saved (Default is '<currentfold>/log
                                  /<arb-name>-<currentdate:$(date +'%d-%m-%Y')>. 
    --live                        Active Live-On Capture mode.
    -v, --version                 Show the version of this program.


${LRed}HUNTER-SEEKER ${Gray}is an Ixian technology. An assassination device that floats 
in mid-air; kills by entering the body and following nerve pathways to vital 
organs. ${DGray}Invented by ${WGray}Frank Herbert ${DGray}in ${WGray}Dune: ${DGray}\"From behind the headboard 
slipped a tiny ${LRed}hunter-seeker ${DGray}no more than five centimeters long.\"
\"It was a ravening sliver of metal guided by some near-by hand and eye.\"

"
  exit 1
}

#####MAIN MENU#####
function MainMenu()
{

clear
if [ -d $logpath ]; then
 logpath=$dirpath/log
fi

tput setaf 196; figlet -f slant Hunter-Seeker; tput sgr0
echo -e "${WGray}[ Jacurutu | https://github.com/RandomLinoge ]" | sed 's/^/          /'
echo -e -n "${LRed} 
Hunter-Seeker ${MGray}is a tool used for basic analysis of URL links, IP addresses, 
extracting and analysing suscpicous files and detect potential malware.

"
echo -e "${WGray}Main Menu: "
echo -e "${Gray}1. Network Analysis"
echo -e "${Gray}2. File Analysis"
echo -e "${Gray}3. Live-On Mode"
echo -e "${Gray}x. Exit Program"
read -p "$(echo -e ${WGray}"Choose: ")" MainOptions
  case $MainOptions in
  1)
    NetAn
    ;;
  2)
    FileAn
    ;;
  3)
  clear
  echo -n -e "
$Gray[$LRed+$Gray] ${LRed}Hunter-Seeker ${WGray}started analysis: "${Gray}$(ip route | tail -1 | cut -d " " -f1)"     ${WGray}[Press any key to break]
"
    LiveOn
    ;;
  x)
    Exit
    ;;
  *)
    echo -e -n "$Gray
Incorret Option. Try Again.
"
    sleep 1
    MainMenu
    ;;
  esac
}

#####MENU FOR FILE ANALYSIS#####
function FileAn()
{
 if [ -z $VT ]
  then
      echo "Installing VirusTotal CLI"
      wget https://github.com/VirusTotal/vt-cli/releases/download/0.10.4/Linux64.zip > /dev/null 2>&1
      unzip Linux64.zip
      rm Linux64.zip*
  fi
  clear
  echo -e -n "
  
${Gray}Checking for an existing VirusTotal API..."
  echo
  sleep 2
  echo
  if [ -f "/home/$(echo ${SUDO_USER:-${USER}})/.vt.toml" ]; then
    echo -e "${WGray}VirusTotal API found!"
    sleep 2
    VTHash=VTAPI
  else
    read -p "$(echo -e ${Gray}"Do you have a secret key to decrypt admin's VirusTotal API? (y/n): ${WGray}")" SecretYN
    case $SecretYN in
    y|Y)
      read -s -p "$(echo -e ${Gray}"Enter your secret key to decrypt VirusTotal API: ${WGray}")" VTSecret
      if [ -z $VTSecret ]
      then
        clear
        echo -e "${Gray}You have not entered a secret key."
        sleep 1
        read -s -p "$(echo -e ${Gray}"Enter your VirusTotal API to activate VirusTotal CLI: ${WGray}")" VTHash
        ./vt init $VTHash 2>/dev/null
        if [ -z $VTHash ]
        then
          echo
          echo -e "${Gray}Register an API for VirusTotal to use this feature and try again."
          sleep 3
          MainMenu
        fi
      fi
      ;;
    n|N)
      clear
      if [ -z $VTSecret ]
      then
        echo -e "${Gray}"; ./vt init 2>/dev/null
        if [ -z $VTHash ]
        then
          echo
          echo -e "${DGray}Register an API for VirusTotal to use this feature and try again."
          sleep 3
          MainMenu
        fi
      fi
      ;;
    esac
  fi
clear
tput setaf 196; figlet -f smslant  Hunter-Seeker; tput sgr0
echo -e "${WGray}File Analysis Options:${reset}"
echo
echo -e "${Gray}1. Upload a potential malware hash of a file for analysis."
echo -e "${Gray}2. Upload a log file with multiple IP/URLs for analysis [addresses should be segregated line by line]."
echo -e "${Gray}3. Upload a batch file with multiple hashes for analysis."
echo -e "${Gray}x. Back to Main Menu"
read -p "$(echo -e ${WGray}"Choose: ")" FileAnOptions
  clear
  case $FileAnOptions in
  1)
    echo
    read -p "$(echo -e ${Gray}"Enter a file hash to analyze [example: ${WGray}"76cdb2bad9582d23c1f6f4d868218d6c"${Gray}]: 
"$WGray)" FileHash
    echo
    echo -e "${Gray}Analyzing file hash ${WGray}$(echo $FileHash | cut -d"/" -f2 2>/dev/null) ${Gray}for malicious code."
    sleep 3
    ./vt file $FileHash > malfilechk
    TotalVotes=$(./vt file $FileHash | grep "malici" | tail -n1 | cut -d":" -f2)
    if [ -d "$logpath/" ]; then
      if [ -f "$logpath/HuntSeek-MalFile-$(date +'%d-%m-%Y').log" ]; then
        cat malfilechk >> $logpath/HuntSeek-MalFile-$(date +'%d-%m-%Y').log
      else
        cat malfilechk > $logpath/HuntSeek-MalFile-$(date +'%d-%m-%Y').log
      fi
    else
      mkdir log 2>/dev/nul
      cat malfilechk > $logpath/HuntSeek-MalFile-$(date +'%d-%m-%Y').log
    fi
    echo -e "${Gray}Analyzing malicious activity in ${WGray}$(echo $(cat malfilechk | grep "filename" | tail -n1))"
    sleep 1
    echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-MalFile-$(date +'%d-%m-%Y').log"
    sleep 3
    echo 
    echo -e "${WGray}--Total Votes--${reset}"
    sleep 1.5
    echo -e "${LRed}Malicious: ${WGray}$TotalVotes"
    sleep 4
    MainMenu
    ;;
  2)
    echo
    read -p "$(echo -e ${Gray}"Enter a file path to analyze: [usage: \"/../<filename.ext>\"]: "${WGray})" BatchName
    echo -e "${Gray}Analyzing malicious activity in the IoC file provided -${WGray} $BatchName 2>/dev/null    ${WGray}[Press any key to break]"
    sudo awk 'BEGIN{ ORS="" } { for ( i=1; i<= NF ; i++){ print $i"\n"  }  }' $BatchName | sort -u --sort=n | sudo tee batchchk >/dev/nul
    file=$(cat batchchk) 
    for line in $file
    do
      sleep 1
      if [ -s malchk ];
      then
       sudo ./vt file $line --apikey $VTAPI | sudo tee malchk2 >/dev/null
        ID=$(cat malchk2 | grep -i "_id" | head -n1 | cut -d":" -f2)
        FileCreation=$(cat malchk2 | grep -i "creation" | head -n1 | cut -d"#" -f2)
        FileType=$(cat malchk2 | grep "file_type" | cut -d":" -f2)
      fi
      if ! [ -s malchk ];
      then
        ./vt url $line > malchk 2>/dev/null
        ID=$(cat malchk | grep -i "url" | tail -n1 | cut -d"\"" -f2)
      fi
      echo -e "${MGray}[${WGray}ID:\033[38;5;132m"$ID"\033[38;5;253m]"
      echo -e "${MGray}[${WGray}Creation: \033[38;5;132m$FileCreation\033[38;5;253m]"
      echo -e "${MGray}[${WGray}Filetype: \033[38;5;132m\\n$FileType\033[38;5;253m]"
      sudo cat malchk2 | grep "total_votes" -2 | grep malicious | head -n1 | cut -d":" -f2 | sudo tee malchk3 >/dev/null
      sleep 1.5
      sudo cat malchk2 | grep "malicious:" | sort -u |  cut -d":" -f2 | sudo tee malchk3 >/dev/null
      if [ $(cat malchk3 | grep "total_votes" -2 | grep malicious | head -n1 | cut -d":" -f2) = 0 ];
         then
            echo -e "${Wgray}[${LRed}Malicious code found"${WGray}]: ${LRed}$(cat malchk2 | grep "total_votes" -2 | grep malicious | head -n1 | cut -d":" -f2)
         else
            echo -e "${Wgray}[${LBlue}Malicious code found"${WGray}]: ${LGreen}$(cat malchk3 | grep "total_votes" -2 | grep malicious | head -n1 | cut -d":" -f2)
      fi
      sleep 2.5
      read -n 1
      read -t 0.1 -n 1000000
      break
    done
    if [ -d "$logpath/" ]; then
      if [ -f "$logpath/HuntSeek-MalMultifiles-$(date +'%d-%m-%Y').log" ]; then
        cat malchk2 >> $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
      else
        cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
      fi
    else
      mkdir $logpath 2>/dev/null
      cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
    fi
    echo
    echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log"
    sleep 1
    echo 
    sleep 4
    MainMenu
    ;;
  3) 
    echo
    read -p "$(echo -e ${Gray}"Enter a file path to analyze: [usage: \"/../<filename.ext>\"]: "${WGray})" BatchName
    echo -e "${Gray}Analyzing malicious activity in the IoC file provided -${WGray} $BatchName     ${WGray}[Press any key to break]"
    sudo awk 'BEGIN{ ORS="" } { for ( i=1; i<= NF ; i++){ print $i"\n"  }  }' $BatchName | sort -u --sort=n | sudo tee batchchk >/dev/null
    processFile() {
        file="batchchk"
        local IFS="\n"
        while read -r line; do
        sleep 1
        sudo echo -E $line | sudo tee malchk >/dev/null
        if [ -s malchk ];
        then
            sudo ./vt file $(cat malchk) --apikey $VTAPI | sudo tee malchk2 >/dev/null
            ID=$(cat malchk2 | grep -i "_id" | head -n1 | cut -d":" -f2)
            FileCreation=$(cat malchk2 | grep -i "creation" | head -n1 | cut -d"#" -f2)
            FileType=$(cat malchk2 | grep "file_type" | cut -d":" -f2)
        fi
        echo -e "${MGray}[${WGray}ID:\033[38;5;132m"$ID"\033[38;5;253m]"
        echo -e "${MGray}[${WGray}Creation: \033[38;5;132m$FileCreation\033[38;5;253m]"
        echo -e "${MGray}[${WGray}Filetype: \033[38;5;132m\\n$FileType\033[38;5;253m]"
        sudo rm malchk
        sleep 1.5
        cat malchk2 | grep last_analysis -n8 | awk '{ print $2,$3 }' | tail -n7 | sudo tee malchk3 >/dev/null
        echo
        if [ $(cat malchk2 | grep last_analysis -n8 | awk '{ print $2,$3 }' | tail -n7 | grep malicious | cut -d":" -f2) = 0 ]; then
            echo -e "${Wgray}[${LRed}Malicious Analysis Found${WGray}]:{Gray}\\n$(cat malchk3 | awk -v ORS='\\n' 1) "
             if [ -d "$logpath/" ]; then
                if [ -f "$logpath/HuntSeek-MalMultifiles-$(date +'%d-%m-%Y').log" ]; then
                    cat malchk2 >> $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
                else
                    cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
                fi
            else
                mkdir $logpath 2>/dev/null
                cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
            fi
        else
            echo -e "${Wgray}[${LBlue}Analysis found${WGray}]:${LGreen}\\n$(cat malchk3 | awk -v ORS='\\n' 1)"
              if [ -d "$logpath/" ]; then
                if [ -f "$logpath/HuntSeek-MalMultifiles-$(date +'%d-%m-%Y').log" ]; then
                    cat malchk2 >> $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
                else
                    cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
                fi
            else
                mkdir $logpath 2>/dev/null
                cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
            fi
        fi
        sleep 2.5
        read -n 1
        read -t 0.1 -n 1000000
        done < $file
    }
    processFile $(pwd)/batchchk
    echo
    echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log"
    sleep 1
    echo
    sleep 4
    ;;
  x)
    MainMenu
    ;;
  esac
}

#####MENU FOR NETWORK ANALYSIS#####
function NetAn()
{
  if [ -z $VT ]
  then
      echo "Installing VirusTotal CLI"
      wget https://github.com/VirusTotal/vt-cli/releases/download/0.10.4/Linux64.zip > /dev/null 2>&1
      unzip Linux64.zip
      rm Linux64.zip*
  fi
  clear
  echo -e -n "
  
${Gray}Checking for an existing VirusTotal API..."
echo
  sleep 2
  echo
  if [ -f "/home/$(echo ${SUDO_USER:-${USER}})/.vt.toml" ]; then
    echo -e "${WGray}VirusTotal API found!"
    sleep 2
    VTHash=VTAPI
  else
    read -p "$(echo -e ${Gray}"Do you have a secret key to decrypt admin's VirusTotal API? (y/n): ${WGray}")" SecretYN
    case $SecretYN in
    y|Y)
      read -s -p "$(echo -e ${Gray}"Enter your secret key to decrypt VirusTotal API: ${WGray}")" VTSecret
      if [ -z $VTSecret ]
      then
        clear
        echo -e "${Gray}You have not entered a secret key."
        sleep 1
        read -s -p "$(echo -e ${Gray}"Enter your VirusTotal API to activate VirusTotal CLI: ${WGray}")" VTHash
        ./vt init $VTHash 2>/dev/null
        if [ -z $VTHash ]
        then
          echo
          echo -e "${Gray}Register an API for VirusTotal to use this feature and try again."
          sleep 3
          MainMenu
        fi
      fi
      ;;
    n|N)
      clear
      if [ -z $VTSecret ]
      then
        echo -e "${Gray}"; ./vt init 2>/dev/null
        if [ -z $VTHash ]
        then
          echo
          echo -e "${DGray}Register an API for VirusTotal to use this feature and try again."
          sleep 3
          MainMenu
        fi
      fi
      ;;
    esac
  fi
clear
tput setaf 196; figlet -f smslant  Hunter-Seeker; tput sgr0
echo -e "${WGray}Network Analysis Options:${reset}"
echo
echo -e "${Gray}1. Analyze a suspicious URL Address"
echo -e "${Gray}2. Analyze a suspicious IP Address"
echo -e "${Gray}x. Back to Main Menu"
read -p "$(echo -e ${WGray}"Choose: ")" NetAnOptions
  clear
  case $NetAnOptions in
  1)
    echo
    read -p "$(echo -e ${Gray}"Enter an URL to analyze [example: ${WGray}www.google.com${Gray}]: ")" URL
    ./vt url $URL > malchk
    TotalVotes=$(./vt url $URL | grep "malici" | tail -n1 | cut -d":" -f2)
    if [ -d "$logpath/" ]; then
      if [ -f "$logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log" ]; then
        cat malchk >> $logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log
      else
        cat malchk > $logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log
      fi
    else
      mkdir $logpath 2>/dev/nul
      cat malchk > $logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log
    fi
    echo -e "${Gray}Analyzing malicious activity in URL Address - ${WGray}$URL"
    echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log"
    sleep 1
    echo 
    echo -e "${WGray}--Total Votes--${reset}"
    sleep 1.5
    echo -e "${LRed}Malicious: ${WGray}$TotalVotes"
    sleep 4
    sudo rm malchk
    MainMenu
    ;;
  2)
    echo
    read -p "$(echo -e $Gray"Enter an IP to analyze: $WGray")" IP
    ./vt ip $IP > malchk
    if [ -d "$logpath/" ]; then
      if [ -f "$logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log" ]; then
        cat malchk >> $logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log
      else
        cat malchk > $logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log
      fi
    else
      mkdir $logpath 2>/dev/nul
      cat malchk > $logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log
    fi
    TotalVotes=$(./vt ip $IP | grep "malici" | tail -n1 | cut -d":" -f2)
    clear
    echo -e "${Gray}Analyzing malicious activity in IP Address - ${WGray}$IP"
    echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log"
    sleep 1
    echo 
    echo -e "${WGray}--Total Votes--${reset}"
    sleep 1.5
    echo -e "${LRed}Malicious: ${WGray}$TotalVotes"
    sleep 4
    sudo rm malchk
    MainMenu
    ;;
  x)
    MainMenu
    ;;
  esac
}

#####EXIT SCRIPT#####
function Exit()
{
  echo -e -n "
   
"
  echo -e "${MGray}Thank you for using ${LRed}Hunter-Seeker${MGray}." | sed 's/^/         /'
  echo -e "${MGray}Goodbye!${reset}" | sed 's/^/         /'
  echo -n "
   
"
  sleep 0.5
  sudo rm capture.txt capture2.txt mal* batchchk chk2 2>/dev/null 
  exit 1
}
#####IP OR ADDRESS BIND WITHOUT INTERACTIVE MENUS#####
function NetAnBind()
{
  clear
  echo -e "${MGray}Analyzing ${WGray}$(echo $BIND)${Gray} ..."
  sleep 1
  ./vt ip $BIND > BindIPchk 2>/dev/null
  if [ -f BindIPchk ]; then
    if [ ! -s BindIPchk ]; then
      ./vt url $BIND > BindURLchk 2>/dev/null
      echo -e -n "${Gray} [ID: ${WGray}"$(cat BindURLchk | grep -i "_id"  | cut -d"\"" -f2)"${Gray}]"
      cat BindURLchk | grep "total_votes" -2 | grep malicious | head -n1 | cut -d":" -f2 > malchk
      if [ ! $(cat BindIPchk | grep -i "_id"  | cut -d"\"" -f2) = "0" ]
        then
          echo -e "\033[38;5;39m -- ${Gray}[Malicious code found]: ${LGreen}"$(cat malchk) | sed 's/\(^ *\) \( [^ ]\)/\1-\2/'
        else
          echo -e "\033[38;5;39m -- ${Gray}[Malicious code found]: ${LRed}"$(cat malchk) | sed 's/\(^ *\) \( [^ ]\)/\1-\2/'
      fi
    fi
    echo -e -n "${Gray} [ID: ${WGray}"$(cat BindIPchk | grep -i "_id"  | cut -d"\"" -f2)"${Gray}]"
    cat BindIPchk | grep malicious | tail -n1 | cut -d":" -f2 > malchk
    if [ ! $(cat BindIPchk | grep -i "_id"  | cut -d"\"" -f2) = "0" ];
      then
        echo -e "\033[38;5;39m -- ${Gray}[Malicious code found]: ${LGreen}"$(cat malchk) | sed 's/\(^ *\) \( [^ ]\)/\1-\2/'
      else
        echo -e "\033[38;5;39m -- ${Gray}[Malicious code found]: ${LRed}"$(cat malchk) | sed 's/\(^ *\) \( [^ ]\)/\1-\2/'
    fi
  fi
  echo
  sleep 2
  if [ -d "$logpath/" ]; then
    if [ -f "$logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log" ]; then
      cat malchk >> $logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log
    else
      cat malchk > $logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log
    fi
    if [ -f "$logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log" ]; then
      cat malchk >> $logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log
    else
      cat malchk > $logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log
    fi
  else
    mkdir $logpath 2>/dev/null
    if [ -f "$logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log" ]; then
      cat malchk > $logpath/HuntSeek-MalIP-$(date +'%d-%m-%Y').log
    fi
    if [ -f "$logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log" ]; then
      cat malchk > $logpath/HuntSeek-MalURL-$(date +'%d-%m-%Y').log
    fi
  fi
  echo
  echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-MalLink-$(date +'%d-%m-%Y').log"
  sleep 2
  Exit
  
}
#####FILEBATCH BIND WITHOUT INTERACTIVE MENUS#####
function FileAnBind()
{
clear
echo -e "${Gray}Analyzing malicious activity in the IoC file provided -${WGray} $BIND     ${WGray}[Press any key to break]"
sudo awk 'BEGIN{ ORS="" } { for ( i=1; i<= NF ; i++){ print $i"\n"  }  }' $BIND | sort -u --sort=n | sudo tee batchchk >/dev/null
processFile() {
    file=$BIND
    local IFS="\n"
    while read -r line; do
    sleep 1
    sudo echo -E $line | sudo tee malchk >/dev/null
    if [ -s malchk ];
    then
        sudo ./vt file $(cat malchk) --apikey $VTAPI | sudo tee malchk2 >/dev/null
        ID=$(cat malchk2 | grep -i "_id" | head -n1 | cut -d":" -f2)
        FileCreation=$(cat malchk2 | grep -i "creation" | head -n1 | cut -d"#" -f2)
        FileType=$(cat malchk2 | grep "file_type" | cut -d":" -f2)
    fi
    echo -e "${MGray}[${WGray}ID:\033[38;5;132m"$ID"\033[38;5;253m]"
    echo -e "${MGray}[${WGray}Creation: \033[38;5;132m$FileCreation\033[38;5;253m]"
    echo -e "${MGray}[${WGray}Filetype: \033[38;5;132m\\n$FileType\033[38;5;253m]"
    sudo rm malchk
    sleep 1.5
    cat malchk2 | grep last_analysis -n8 | awk '{ print $2,$3 }' | tail -n7 | sudo tee malchk3 >/dev/null
    echo
    if [[ $(cat malchk2 | grep last_analysis -n8 | awk '{ print $2,$3 }' | tail -n7 | grep malicious | cut -d":" -f2) == 0 ]]; then
        echo -e "${Wgray}[${LRed}Malicious Analysis:${WGray}]{Gray}\\n$(cat malchk3 | awk -v ORS='\\n' 1) "
        if [ -d "$logpath/" ]; then
            if [ -f "$logpath/HuntSeek-MalMultifiles-$(date +'%d-%m-%Y').log" ]; then
                cat malchk2 >> $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
            else
                cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
            fi
       else
            mkdir $logpath 2>/dev/null
            cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
        fi
    else
        echo -e "${Wgray}[${LBlue}Analysis:${WGray}]${LGreen}\\n$(cat malchk3 | awk -v ORS='\\n' 1)"
        if [ -d "$logpath/" ]; then
            if [ -f "$logpath/HuntSeek-MalMultifiles-$(date +'%d-%m-%Y').log" ]; then
                cat malchk2 >> $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
            else
                cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
            fi
        else
            mkdir $logpath 2>/dev/null
            cat malchk2 > $logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log
        fi
    fi
    sleep 2.5
    read -n 1
    read -t 0.1 -n 1000000
    done < $file
}
processFile $(pwd)/batchchk
echo
echo -n"
    
"
echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-MalMultFiles-$(date +'%d-%m-%Y').log"
sleep 4
Exit
   
}
#####SCRIPT VERSION#####
function Version()
{
  clear
  tput setaf 196; figlet -f mini Hunter-Seeker| sed 's/^/   /'; tput sgr0  
  echo -e "${DGray}[ ${WGray}Jacurutu ${DGray}| ${WGray}https://github.com/RandomLinoge ${DGray}| ${WGray}v1.3.6]"
  echo
  sleep 1
}

#####LIVE ON CAPTURE#####
function LiveOn()

{
sudo tshark -i eth0 -t ad -n -T fields -e ip.src -e dns.qry.name -Y "dns.flags.response eq 0" -a duration:15 2>/dev/null | sudo tee capture.txt > /dev/null
sort  capture.txt | column -t -s $'\t' > capture2.txt
if [ -s capture2.txt ]; then
  for line in capture2.txt
  do
    cat $line | awk '{print "\033[0m[\033[38;5;132m"$1"\033[0m]","[\033[38;5;196m"$2"\033[0m]"}' | sed -r "s/\s/\ accessed /g" | xargs -L 1 echo -e `TZ="Asia/Jerusalem" date +'\033[0m[\033[38;5;250m%A, %b %d, %Y %H:%M:%S\033[0m]\033[38;5;39m'` --- $1 2>/dev/null > chk2
    sleep 2
    cat chk2
    if [ -d "$logpath/" ]; then
      if [ -f "$logpath/HuntSeek-LiveOn-$(date +'%d-%m-%Y').log" ]; then
        cat chk2 >> $logpath/HuntSeek-LiveOn-$(date +'%d-%m-%Y').log
      else
        cat chk2 > $logpath/HuntSeek-LiveOn-$(date +'%d-%m-%Y').log
      fi
    else
      mkdir $logpath 2>/dev/nul
      cat chk2 > $logpath/HuntSeek-LiveOn-$(date +'%d-%m-%Y').log
    fi
    read -n 1
    sudo pkill tshark   #kill tshark
    read -t 0.1 -n 1000000
    echo
    echo -e "${Gray}Log file saved - ${WGray}$logpath/HuntSeek-LiveOn-$(date +'%d-%m-%Y').log"
    sleep 4
    Exit
  done
fi
LiveOn
}

#####BINDING ATTRIBUTES AND VARIABLES DESCRIBED IN FULL HELP MENU#####
  if [ "$1" == "--live" ]; then
    clear
    echo -n -e "
${Gray}[${LRed}+${Gray}] ${LRed}Hunter-Seeker ${WGray}started analysis: "${Gray}$(ip route | tail -1 | cut -d " " -f1)"    ${WGray}[Press any key to break]

"
    LiveOn
  fi

  if [[ "$1" == "-b" && ! -z "$2" ]] && [[ "$3" == "-o" && ! -z "$4" ]]; then
                                 
    clear
    logpath=$4
    BIND=$2
    NetAnBind
  fi

  if [[ "$1" == "-b" && ! -z $2 ]] && [[ "$3" == "-o" && -z $4 ]]; then
    echo
    echo -e -n "${MGray}
Incorret use of program pre-options.
    
referring to help options - ${WGray}\"./Hunterseeker --help\"${MGray}.
Example of usage: ${WGray}\"./Hunterseeker -b [IP|Hostname] -o [Log output directory]\"
"
    Exit
  fi

  if [[ "$1" == "-m" && ! -z "$2" ]] && [[ "$3" == "-o" && ! -z "$4" ]]; then
    clear
    logpath=$4
    BIND=$2
    FileAnBind
  fi

  if [[ "$1" == "-m" && ! -z "$2" ]] && [[ "$3" == "-o" && -z "$4" ]]; then
    echo
    echo -e -n "${MGray}
Incorret use of program pre-options.
    
referring to help options - ${WGray}\"./Hunterseeker --help\"${MGray}.
Example of usage: ${WGray}\"./Hunterseeker -m [Filename] -o [Log output directory]\"
"
    Exit
  fi

  if [[ "$1" == "-m" && -z "$2" ]]; then
    echo
    echo -e -n "${MGray}
Incorret use of program pre-options.
    
referring to help options - ${WGray}\"./Hunterseeker --help\"${MGray}.
Example of usage: ${WGray}\"./Hunterseeker -m [Filename] -o [Log output directory]\"
"
    Exit
  fi

  if [[ "$1" == "-m" && ! -z "$2" ]]; then
    BIND=$2
    FileAnBind
  fi

  if [ "$1" == "-o" ]; then
    echo
    echo -e -n "${MGray}
Incorret use of program pre-options.
    
referring to help options - ${WGray}\"./Hunterseeker --help\"${MGray}.
Example of usage: ${WGray}\"./Hunterseeker -i|--interactive -o [Log output directory]\"
"
    Exit
  fi

  if [ -z "$1" ]; then
    MainMenu
  fi

  if [[ $1 == "-i" || $1 == "--interactive" ]]; then
    MainMenu
  fi
  
  if [ "$2" == "-o" ] && [ -d $3 ]; then
  logpath=$3
  fi

  if [ "$2" == "-o" ] && [ ! -d $3 ]; then 
    echo
    echo -e -n "${MGray}
Incorret use of program pre-options.
    
referring to help options - ${WGray}\"./Hunterseeker --help\"${MGray}.
Example of usage: ${WGray}\"./Hunterseeker -b [IP|Hostname] -o [Log output directory]\"
"
    Exit
  fi

  if [[ "$1" == "-b" && -z $2 ]]; then
    echo
    echo -e -n "
${MGray}Incorret use of program pre-options.
    
referring to help options - ${WGray}\"./Hunterseeker --help\"${MGray}.
Example of usage: ${WGray}\"./Hunterseeker -b [IP|Hostname] -o [Log output directory]\"
"
    Exit
  fi

  if [ "$1" == "-h" ]; then
    HelpShort
  fi

  if [[ "$1" == "-v" || "$1" == "--version" ]]; then
    Version
  fi

  if [ "$1" == "--help" ]; then
    HelpFull
  fi
