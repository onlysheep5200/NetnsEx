ovs-vsctl del-br ovsbr1
ovs-vsctl add-br ovsbr1
ovs-vsctl set-controller ovsbr1 tcp:10.109.242.219:6633
ip link set dev ovsbr1 up
