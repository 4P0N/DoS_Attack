# DoS_Attack
--help	show this manual \n
--a   	attack address ( must be given )
--port   port to be attacked ( Default: 80 ) 
--sp     spoofed IP address ( Default: random on each packet )


Usage:

1) sudo ./a.out -a 10.0.5.5 -sp 10.0.5.6 -port 53
2) sudo ./a.out -a 10.0.5.5 

*** -a must be given, others are optional