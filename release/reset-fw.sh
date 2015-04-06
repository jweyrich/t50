#!/bin/bash

iptables -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT

