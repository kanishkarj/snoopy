# Snoopy
[![Crates.io](https://img.shields.io/crates/v/snoopy.svg)](https://crates.io/crates/snoopy) 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://travis-ci.com/kanishkarj/snoopy.svg?token=jy9kvPoUgCS7spyshyKq&branch=master)](https://travis-ci.com/kanishkarj/snoopy)

A highly configurable multi-threaded packet sniffer and parser build in rust-lang.  

## Features

* Capturing packets and encoding them to Pcap files, or print them onto console.
* While capturing packets, various configuration parameters can be specified. 
* Parse Pcap files and print them to console, or extract more verbose information from each packet and store them to JSON file.
* Multi-threaded parsing of packets.
* Filter packets while parsing and capturing.
* Currently supports the following protocols :
  * Ethernet
  * Ipv4
  * Ipv6
  * Arp
  * Tcp
  * Udp
  * Dns
  * Tls

the Json file is generated like given below : 

```Json

[{
  "Ok": {
    "len": 11,
    "timestamp": "1234567890.123456",
    "headers": [{
        "Tls": {
          ...
        }
      },
      {
        "Tcp": {
          ...
        }
      }, {
        "Ipv4": {
          ...
        }
      }, {
        "Ether": {
          ...
        }
      }
    ],
    "remaining": [...]
  }
},
...
]

```

## Installation

Ensure that you have `libpcap-dev` (ubuntu) or the corresponding package installed on your system.
Run the following commands in the command line inside the folder : 

```zsh
cargo install snoopy
```

## Quick-Start

To Capture packets and print them onto the console : 
```zsh
➜ sudo snoopy capture run                                          
--------------------
Sniffing  wlp3s0
-------------------- 


Source IP              | Source Port  | Dest IP                | Dest Port    | Protocol     | Length       | Timestamp            |
------------------------------------------------------------------------------------------------------------------------------------
52.216.185.195         | 443          | 10.20.197.103          | 38522        | Tcp          | 10078        | 1562310108.589373                  
10.20.197.103          | 38522        | 52.216.185.195         | 443          | Tcp          | 54           | 1562310108.589468                  
52.216.185.195         | 443          | 10.20.197.103          | 38522        | Tcp          | 10078        | 1562310108.890490                  
10.20.197.103          | 38522        | 52.216.185.195         | 443          | Tcp          | 54           | 1562310108.890547                  
52.216.185.195         | 443          | 10.20.197.103          | 38522        | Tcp          | 1486         | 1562310109.197739                  
10.20.197.103          | 38522        | 52.216.185.195         | 443          | Tcp          | 54           | 1562310109.197795                  
52.216.185.195         | 443          | 10.20.197.103          | 38522        | Tcp          | 1486         | 1562310109.197841                  
10.20.197.103          | 38522        | 52.216.185.195         | 443          | Tcp          | 66           | 1562310109.197865                  
52.216.185.195         | 443          | 10.20.197.103          | 38522        | Tcp          | 2918         | 1562310109.197887                  
10.20.197.103          | 38522        | 52.216.185.195         | 443          | Tcp          | 74           | 1562310109.197906                  
52.216.185.195         | 443          | 10.20.197.103          | 38522        | Tcp          | 1486         | 1562310109.197965                  
10.20.197.103          | 38522        | 52.216.185.195         | 443          | Tcp          | 74           | 1562310109.197984                  
35.154.102.71          | 443          | 10.20.197.103          | 56572        | Tls          | 160          | 1562310109.262324                  
10.20.197.103          | 56572        | 35.154.102.71          | 443          | Tcp          | 66           | 1562310109.262383                  
```

Capture packets and save them to Pcap files :

```shell
➜ sudo snoopy capture run --timeout 10000 --savefile captured.pcap
```

> Note: For capturing packets the user needs root user permissions to capture network packets.

Parse Pcap files and print to console:

```shell
➜ snoopy parse ./Sample/captured.pcap
```

Parse Pcap files and print to console (with filters):

```shell
➜ snoopy parse ./Sample/captured.pcap --filter "tcp port 443"
```

> The above command will print all TCP packets with source/destination port 443.


Parse Pcap files and save to JSON file:

```shell
➜ snoopy parse ./Sample/captured.pcap --savefile ./parsed.json
```

## Documentation

All commands and sub-commands are listed below : 

```zsh
USAGE:
    snoopy [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    capture    Capture packets from interfaces.
    help       Prints this message or the help of the given subcommand(s)
    parse      Parse pcap files.

```
```zsh
USAGE:
    snoopy capture [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    list    List all interfaces.
    run     Start capturing packets.
```
```zsh
USAGE:
    snoopy capture run [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -p, --promisc    Set promiscuous mode on or off. By default, this is off.
    -r, --rfmon      Set rfmon mode on or off. The default is maintained by pcap.
    -V, --version    Prints version information

OPTIONS:
    -b, --buffer_size <buffer_size>    Set the buffer size for incoming packet data. The default is 1000000. This should
                                       always be larger than the snaplen.
        --handle <device_handle>       Specify the device interface
    -f, --filter <filter>              Set filter to the capture using the given BPF program string.
        --precision <precision>        Set the time stamp precision returned in captures (Micro/Nano).
        --savefile <savefile>          Save the captured packets to file.
    -s, --snaplen <snaplen>            Set the snaplen size (the maximum length of a packet captured into the buffer).
                                       Useful if you only want certain headers, but not the entire packet.The default is
                                       65535.
    -t, --timeout <timeout>            Set the read timeout for the Capture. By default, this is 0, so it will block
                                       indefinitely.
        --tstamp_type <tstamp_type>    Set the time stamp type to be used by a capture device (Host / HostLowPrec /
                                       HostHighPrec / Adapter / AdapterUnsynced).

```
```zsh
USAGE:
    snoopy parse [OPTIONS] <file_name>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f, --filter <filter>        Set filter to the capture using the given BPF program string.
    -s, --savefile <savefile>    Parse the packets into JSON and save them to memory.

ARGS:
    <file_name>   
```

> Note: The filters can be defined according to the syntax specified [here](http://biot.com/capstats/bpf.html).

## Docker

Run the following commands in the command line inside the folder : 

```zsh
docker build -t snoopy .
docker container run -it snoopy
```

## Build

Run the following command in the command line inside the folder : 

```zsh
cargo build
```

## Todo

* Benchmarking
* Support for other protocols

## License

This project is under the MIT license.