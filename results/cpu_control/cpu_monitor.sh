#!/bin/bash

### Usage Metrics
monitor_cpu_usage () {
    cpu_usage=0
    min_cpu=100
    max_cpu=0
    counter=1
    while [ $counter -le 60 ]
    do
        now_cpu=$(mpstat 1 1 | awk 'END{print 100-$NF}')
        cpu_usage="$( bc <<<"$cpu_usage + $now_cpu" )"
        #printf 'now_cpu %f\n' "$now_cpu"
        if [ $( echo "$now_cpu < $min_cpu" | bc ) -eq 1 ]; then
            min_cpu=$now_cpu
        fi
        if [ $( echo "$now_cpu > $max_cpu" | bc ) -eq 1 ]; then
            max_cpu=$now_cpu
        fi
        #printf 'aggregate %f\n' "$cpu_usage"
        #printf 'min_cpu %f\n' "$min_cpu"
        ((counter++))
    done
    ((counter--))
    #echo $counter
    avg_cpu=$( echo "$cpu_usage / $counter" | bc -l )
    printf 'min_cpu %f\n' "$min_cpu"
    printf 'avg_cpu %f\n' "$avg_cpu"
    printf 'max_cpu %f\n' "$max_cpu"
}

monitor_cpu_usage

