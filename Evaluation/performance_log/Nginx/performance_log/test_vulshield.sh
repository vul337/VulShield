

#!/bin/bash

#for i in $(seq 1 10) 
#do
#ab -n 100000 -c 10 -p ../post.data -T application/x-www-form-urlencoded http://127.0.0.1:80/index.html >>log10_vul;
#done

#sleep 2

#for i in $(seq 1 10)
#do
#ab -n 100000 -c 100 -p ../post.data -T application/x-www-form-urlencoded http://127.0.0.1:80/index.html >>log100_vul;
#done

#sleep 2

#for i in $(seq 1 10)
#do
#ab -n 100000 -c 1000 -p ../post.data -T application/x-www-form-urlencoded http://127.0.0.1:80/index.html >>log1000_vul;
#done

#sleep 2

for i in $(seq 1 10)
do
ab -n 100000 -c 10000 -p ../post.data -T application/x-www-form-urlencoded http://127.0.0.1:80/index.html >>log10000_vul;
done



