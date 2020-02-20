docker stop puredb
docker rm puredb
CONT=`docker run --name puredb -e MYSQL_ROOT_PASSWORD=qwerty -p 3306:3306 -d mariadb:latest`
sleep 5
cat pure.sql | docker exec -i $CONT /usr/bin/mysql