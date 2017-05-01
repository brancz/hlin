h1: _output/linux/amd64/hlin --port 10000 --cert-file _output/certs/server1.crt --key-file _output/certs/server1.key --ca-file _output/certs/ca.crt --peer h2:_output/certs/server2.crt:localhost:10001 --peer h3:_output/certs/server3.crt:localhost:10002 --etcd http://127.0.0.1:2379
h2: _output/linux/amd64/hlin --port 10001 --cert-file _output/certs/server2.crt --key-file _output/certs/server2.key --ca-file _output/certs/ca.crt --peer h1:_output/certs/server1.crt:localhost:10000 --peer h3:_output/certs/server3.crt:localhost:10002 --etcd http://127.0.0.1:2379
h3: _output/linux/amd64/hlin --port 10002 --cert-file _output/certs/server3.crt --key-file _output/certs/server3.key --ca-file _output/certs/ca.crt --peer h1:_output/certs/server1.crt:localhost:10000 --peer h2:_output/certs/server2.crt:localhost:10001 --etcd http://127.0.0.1:2379
e1: etcd --data-dir _output/etcd-data

