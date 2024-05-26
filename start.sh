if [ -z "$1" ]
then
    echo "Usage: $0 IP PORT\n"
    exit 1
fi
if [ -z "$2" ]
then
    echo "Usage: $0 IP PORT\n"
    exit 1
fi

make dns_svr
./dns_svr $1 $2
