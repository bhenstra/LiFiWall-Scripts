#!/bin/bash


# -------
# LICENSE
# -------
#
# The following license applies to this software.
#
# BSD Zero Clause License
# Copyright (C) 2023 by Bouke Jasper Henstra <bouke{at}ict-diensten{dot}com>
# Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


# ----
# INFO
# ----
#
# Version 0.4. 2023-12-26 (yyyy-mm-dd).
# Please find information in the file "fwall.sh.read.me.txt".


# --------------
# BEGIN SETTINGS
# --------------

# Define WhiteLists

  # Whitelist SSH (accept SSH connections from these IPs)

    WL_SSH="77.xxx.yyy.155,185.xxx.yyy.104/29"

  # Whitelist GRE (accept GRE connections from these IPs)

    WL_GRE="77.xxx.yyy.155"

# Define ports to forward via GRE

  # TCP Ports

    GRE_TCP_PORTS="25,80,443,465,587,995"

# Define public interface name (this is eg "eth0")

  INT_PUB="ens6"

# Define GRE interface name (this is eg "gre1") and destination IP (this is the other end of the tunnel, eg the firewall's IPv4)

  INT_GRE="gre1"
  DST_GRE="172.30.250.1"

# Define iptables executable (Debian 12 appears to use xtables-nft-multi by default)
  # IPT="/sbin/iptables"
    IPT="/usr/sbin/xtables-nft-multi iptables"

# Define generic network data (please do not edit)
  NET_PRIV_A="10.0.0.0/8"
  NET_PRIV_B="172.16.0.0/12"
  NET_PRIV_C="192.168.0.0/16"

# --------------
# END   SETTINGS
# --------------


# ------------
# BEGIN SCRIPT
# ------------

# Functions

  flush_iptables_rules() {

  # This function will be called to flush the iptables rules. 
    echo "Flushing iptables rules"

    $IPT -F
    $IPT -X
    $IPT -Z
    $IPT -t nat -F
    $IPT -t nat -X
    $IPT -t mangle -F
    $IPT -t mangle -X
    $IPT -t raw -F
    $IPT -t raw -X
  }

  set_default_policy() {

  # This function will be called to set the ruleset. 
    echo "Setting default firewall policy"
  
    # Set the default firewall policy

      $IPT -P INPUT DROP
      $IPT -P FORWARD DROP
      $IPT -P OUTPUT DROP
  }

  set_enable_forwarding() {

    # Allow the forwarding of traffic (forwarding should be configured through sysctl; this is a safeguard to ensure forwarding is enabled).
      echo "Enabling forwarding"

      echo "1" > /proc/sys/net/ipv4/conf/all/forwarding
      #echo "1" > /proc/sys/net/ipv6/conf/all/forwarding
  }

  set_firewall_rules() {

  echo "Setting firewall rules"

    # Set default rules for established,related states

      $IPT -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
      $IPT -I OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Set default rules for loopback network

      $IPT -I INPUT ! -i lo -s 127.0.0.0/8 -j REJECT
      $IPT -I INPUT -i lo -j ACCEPT
      $IPT -I OUTPUT -o lo -j ACCEPT

    # Allow default outbound rules - egress

      $IPT -A OUTPUT -o $INT_PUB -p tcp --dport 80 -j ACCEPT
      $IPT -A OUTPUT -o $INT_PUB -p tcp --dport 443 -j ACCEPT
      $IPT -A OUTPUT -o $INT_PUB -p udp --dport 53 -j ACCEPT
      $IPT -A OUTPUT -o $INT_PUB -p udp --dport 123 -j ACCEPT

    # Allow SSH from certain IP addresses

      $IPT -A INPUT -i $INT_PUB -p tcp --dport 22 -s $WL_SSH -m comment --comment "Allow SSH ingress" -j ACCEPT 

    # Allow GRE - this is to establish the GRE tunnel

      $IPT -A INPUT -i $INT_PUB -p 47 -s $WL_GRE -m comment --comment "Allow GRE ingress" -j ACCEPT
      $IPT -A OUTPUT -o $INT_PUB -p 47 -d $WL_GRE -m comment --comment "Allow GRE egress" -j ACCEPT

    # Allow ICMP echo req GRE - to be able to ping from the other end of the GRE tunnel

      $IPT -A INPUT -i $INT_GRE -p icmp --icmp-type 8 -j ACCEPT
      $IPT -A OUTPUT -o $INT_GRE -p icmp -j ACCEPT

    # Allow incoming traffic on $INT_PUB and forward it to $DST_GRE

      $IPT -A INPUT -i $INT_PUB -p tcp --match multiport --dport $GRE_TCP_PORTS -m comment --comment "Allow $GRE_TCP_PORTS ingress" -j ACCEPT
      $IPT -A PREROUTING -t nat -p tcp --match multiport --dport $GRE_TCP_PORTS -j DNAT --to-destination $DST_GRE

    # Allow forwarding incoming traffic through the GRE tunnel

      $IPT -A FORWARD -i $INT_PUB -o $INT_GRE -j ACCEPT
      $IPT -A FORWARD -i $INT_GRE -o $INT_PUB -m state --state ESTABLISHED,RELATED -j ACCEPT

    # GRE forwarding rules
      $IPT -A INPUT -i $INT_GRE ! -d $NET_PRIV_A -j REJECT
      $IPT -A INPUT -i $INT_GRE ! -d $NET_PRIV_B -j REJECT
      $IPT -A INPUT -i $INT_GRE ! -d $NET_PRIV_C -j REJECT
      $IPT -A INPUT -i $INT_GRE -j ACCEPT
  }

  check_exit_status() {
    # Check the exit status of the last command
    if [ $? -ne 0 ]; then
        echo "Error: $1"
        exit 1
    fi
  }

# Call functions

  flush_iptables_rules
  # Check the exit status of the last command
    check_exit_status "Flushing iptables rules"

  set_default_policy
  # Check the exit status of the last command
    check_exit_status "Setting default firewall policy"

  set_enable_forwarding
  # Check the exit status of the last command
    check_exit_status "Enabling forwarding"

  set_firewall_rules
  # Check the exit status of the last command
    check_exit_status "Setting firewall rules"

# ------------
# END   SCRIPT
# ------------

