#!/bin/bash

#####################################################
#                                                   #
#                                                   #
#                FIREWALL DA EMPRESA                #
#                                                   #
#                                                   #
#####################################################


# Ativando roteamento no Kernel

echo "1" > /proc/sys/net/ipv4/ip_forward

# Variaveis de IP interno, externo e path do IPtables

IPT='/sbin/iptables'
MODPROBE='/sbin/modprobe'
LanExt=10.0.2.15
LanInt=192.168.0.1
Rede=192.168.0.0/255.255.255.0

# Modulos ativados na inicializacao do sistema

$MODPROBE ip_tables
$MODPROBE ip_conntrack
$MODPROBE iptable_filter
$MODPROBE iptable_mangle
$MODPROBE iptable_nat
$MODPROBE ipt_LOG
$MODPROBE ipt_limit
$MODPROBE ipt_state
$MODPROBE ipt_REDIRECT
$MODPROBE ipt_owner
$MODPROBE ipt_REJECT
$MODPROBE ipt_MASQUERADE
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_nat_ftp
$MODPROBE ipt_LOG
$MODPROBE ipt_limit
$MODPROBE ipt_state
$MODPROBE ipt_REDIRECT
$MODPROBE ipt_owner
$MODPROBE ipt_REJECT
$MODPROBE ipt_MASQUERADE
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_nat_ftp
$MODPROBE ip_gre

echo "Ativando Modulos    [ OK ]"

###################
###FUNCAO  START###
###################

firewall_start() {

echo "Iniciando o Firewall"

#Limpando Regra

$IPT -F
$IPT -X
$IPT -Z
$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -F -t nat
$IPT -X -t nat
$IPT -F -t mangle
$IPT -X -t mangle

echo "Limpando Regras      [ OK ]"

# Alterando as politicas padroes das tabelas(filter, nat e mangle)

################
# Tabela Filter#
################

$IPT -t filter -P INPUT   ACCEPT
$IPT -t filter -P OUTPUT  ACCEPT
$IPT -t filter -P FORWARD ACCEPT

################
# Tabela NAT   #
################
$IPT -t nat -P PREROUTING  ACCEPT
$IPT -t nat -P OUTPUT      ACCEPT
$IPT -t nat -P POSTROUTING ACCEPT

################
# Tabela Mangle#
################

$IPT -t mangle -P PREROUTING ACCEPT
$IPT -t mangle -P OUTPUT     ACCEPT

# Mantendo conexoes ja estabelecidas

$IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT

# Aceita todo o trafego vindo do loopback e indo pro loopback

$IPT -t filter -A INPUT -i lo -j ACCEPT

##################
###  Protecao  ###
##################

# Protege contra Ping da Morte (Ex: Ping of Death)

$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/m -j ACCEPT
$IPT -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/m -j ACCEPT

# Protege contra port scanners avancados (Ex: nmap)

$IPT -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/m -j ACCEPT

# Protecao contra ataques

$IPT -A INPUT -m state --state INVALID -j REJECT

###################
#                 #
#  Tabela Filter  #
#                 #
###################

###################
#      INPUT      #
###################

###################
#      FORWARD    #
###################

#Liberando porta 53 (dns)
$IPT -A FORWARD  -s $Rede -p tcp --dport 53 -j ACCEPT
$IPT -A FORWARD  -s $Rede -p udp --dport 53 -j ACCEPT

#Liberando porta 80 (http)
$IPT -A FORWARD  -s $Rede -p tcp --dport 80 -j ACCEPT
#Liberando porta 443 (https)
$IPT -A FORWARD  -s $Rede -p tcp --dport 443 -j DROP

###################
#      OUTPUT               #
###################

###################
#                                     #
#  Tabela NAT               #
#                                     #
###################

###################
#   PREROUTING        #
###################

###################
#   POSTROUTING      #
###################
# Mascaramento de rede para acesso externo

$IPT -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

###################
#                                     #
#  Tabela Mangle          #
#                                    #
##################


}

###################
### FUNCAO STOP###
###################
firewall_stop() {
echo "Parando firewall e funcionando apenas com mascaramento"

#Limpando Regra

$IPT -F
$IPT -X
$IPT -Z
$IPT -F INPUT
$IPT -F OUTPUT
$IPT -F FORWARD
$IPT -F -t nat
$IPT -X -t nat
$IPT -F -t mangle
$IPT -X -t mangle

echo "Limpando Regras      [ OK ]"

# Alterando as politicas padroes das tabelas(filter, nat e mangle)

################
# Tabela Filter        #
# Tabela Filter       #
###############

$IPT -t filter -P INPUT   ACCEPT
$IPT -t filter -P OUTPUT  ACCEPT
$IPT -t filter -P FORWARD ACCEPT

###############
# Tabela NAT        #
###############

$IPT -t nat -P PREROUTING  ACCEPT
$IPT -t nat -P OUTPUT      ACCEPT
$IPT -t nat -P POSTROUTING ACCEPT

###############
# Tabela Mangle   # 
###############

$IPT -t mangle -P PREROUTING ACCEPT
$IPT -t mangle -P OUTPUT     ACCEPT
# Mantendo conexoes ja estabelecidas

$IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT

# Aceita todo o trafego vindo do loopback e indo pro loopback

$IPT -t filter -A INPUT -i lo -j ACCEPT

################
### Tabela NAT ###
################

# Mascaramento de rede para acesso externo

$IPT -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

echo "Regras Limpas e Firewall Desabilitado"

}

#####################
##FUNCAO  RESTART##
####################
firewall_restart() {
  echo "Reiniciando Firewall..."
  firewall_stop
  sleep 3
  firewall_start
  echo "Firewall Reiniciado!"
}
case "$1" in
'start')
  firewall_start
echo "Firewall Iniciado!"
  ;;
'stop')
  firewall_stop
  ;;
'restart')
  firewall_restart
  ;;
*)
          echo "Opcoes possiveis:"
          echo "firewall start"
          echo "firewall stop"
          echo "firewall restart"


esac