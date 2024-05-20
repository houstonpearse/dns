

for var in "$@"
do
    if [[ "$var" == "1" ]]
        then
        echo A record
        dig +tcp -p 8053 @127.0.0.1 google.com 
    elif [ "$var" == "2" ]
        then
        echo AAAA record
        dig +tcp -p 8053 @127.0.0.1 AAAA aws.com
    elif [ "$var" == "3" ]
        then
        echo multiple AAAA queries
        dig +tcp -p 8053 @127.0.0.1 AAAA google.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA aws.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA youtube.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA google.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA aws.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA youtube.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA google.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA aws.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA youtube.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA google.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA aws.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA youtube.com &
        wait
    elif [ "$var" == "4" ]
        then
        echo domain with no AAAA records
        dig +tcp -p 8053 @127.0.0.1 AAAA amazon.com 
    elif [ "$var" == "5" ]
        then
        echo multiple AAAA queries
        dig +tcp -p 8053 @127.0.0.1 AAAA google.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA aws.com &
        dig +tcp -p 8053 @127.0.0.1 AAAA youtube.com &
        wait
    fi

done
    












