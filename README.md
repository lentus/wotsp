[![Build Status](https://travis-ci.org/lentus/wotsp.svg?branch=concurrent)](https://travis-ci.org/lentus/wotsp) [![GoDoc](https://godoc.org/github.com/lentus/wotsp?status.svg)](https://godoc.org/github.com/lentus/wotsp) [![Go Report Card](https://goreportcard.com/badge/github.com/lentus/wotsp)](https://goreportcard.com/report/github.com/lentus/wotsp)

# W-OTS+
A Go implementation of the Winternitz OTS (W-OTS+), as described in [RFC8391](https://datatracker.ietf.org/doc/rfc8391/).
This implementation supports Winternitz parameters ```w = 4```, ```w = 16``` and ```w = 256```, 
which can be selected by setting the ```Mode``` of the ```Opts``` struct to 
```W4```, ```W16``` or ```W256``` respectively (if no mode is provided, ```W16``` is used).

W-OTS+ was first described in [1]. However, the original design is susceptible 
to multi-target attacks. This issue was solved in [2] with WOTS-T. The RFC 
confusingly refers to W-OTS+, despite including the modifications from 
[2] and thus actually describing WOTS-T.      

## Install

```sh
go get -u https://github.com/lentus/wotsp
```

## Performance
The benchmarks below were optained with `go test -run='^$' -bench .`. These
benchmarks iterate through all relevant configurations of Opts, the mode and
concurrency parameters. Read the docs on the Opts type for more details about
these parameters.

The names of the benchmarks should be read as
`BenchmarkWOTSP/<MethodName>-<Mode>-<Concurrency>-<NumCPU>`.

<details>
    <summary>Benchmarks</summary>
    
    ```
    CPU: Intel(R) Core(TM) i7-5820K CPU @ 3.30GHz
    goos: linux
    goarch: amd64
    pkg: github.com/lentus/wotsp
    BenchmarkWOTSP/GenPublicKey-W4-1-12         	    3000	    528686 ns/op	   10848 B/op	      15 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-2-12         	    3000	    512078 ns/op	   11121 B/op	      17 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-3-12         	    3000	    406027 ns/op	   11394 B/op	      19 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-4-12         	    5000	    351777 ns/op	   11638 B/op	      21 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-5-12         	    5000	    350774 ns/op	   11909 B/op	      23 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-6-12         	    5000	    332991 ns/op	   12161 B/op	      25 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-7-12         	    5000	    315319 ns/op	   12437 B/op	      27 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-8-12         	    5000	    305585 ns/op	   12688 B/op	      29 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-9-12         	    5000	    285246 ns/op	   12960 B/op	      31 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-10-12        	    5000	    318314 ns/op	   13216 B/op	      33 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-11-12        	    5000	    284008 ns/op	   13510 B/op	      35 allocs/op
    BenchmarkWOTSP/GenPublicKey-W4-12-12        	    5000	    327860 ns/op	   13744 B/op	      37 allocs/op
    BenchmarkWOTSP/Sign-W4-1-12                 	    5000	    297997 ns/op	   11093 B/op	      17 allocs/op
    BenchmarkWOTSP/Sign-W4-2-12                 	    5000	    335446 ns/op	   11349 B/op	      19 allocs/op
    BenchmarkWOTSP/Sign-W4-3-12                 	    5000	    262650 ns/op	   11621 B/op	      21 allocs/op
    BenchmarkWOTSP/Sign-W4-4-12                 	   10000	    245845 ns/op	   11877 B/op	      23 allocs/op
    BenchmarkWOTSP/Sign-W4-5-12                 	   10000	    247218 ns/op	   12149 B/op	      25 allocs/op
    BenchmarkWOTSP/Sign-W4-6-12                 	    5000	    241907 ns/op	   12405 B/op	      27 allocs/op
    BenchmarkWOTSP/Sign-W4-7-12                 	   10000	    241170 ns/op	   12677 B/op	      29 allocs/op
    BenchmarkWOTSP/Sign-W4-8-12                 	   10000	    245966 ns/op	   12933 B/op	      31 allocs/op
    BenchmarkWOTSP/Sign-W4-9-12                 	    5000	    250778 ns/op	   13206 B/op	      33 allocs/op
    BenchmarkWOTSP/Sign-W4-10-12                	    5000	    245817 ns/op	   13461 B/op	      35 allocs/op
    BenchmarkWOTSP/Sign-W4-11-12                	    5000	    252121 ns/op	   13749 B/op	      37 allocs/op
    BenchmarkWOTSP/Sign-W4-12-12                	    5000	    269160 ns/op	   13989 B/op	      39 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-1-12     	    5000	    255714 ns/op	    6069 B/op	      14 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-2-12     	    5000	    239534 ns/op	    6325 B/op	      16 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-3-12     	   10000	    184492 ns/op	    6597 B/op	      18 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-4-12     	   10000	    167097 ns/op	    6853 B/op	      20 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-5-12     	   10000	    168060 ns/op	    7125 B/op	      22 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-6-12     	   10000	    153551 ns/op	    7381 B/op	      24 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-7-12     	   10000	    156074 ns/op	    7653 B/op	      26 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-8-12     	   10000	    154310 ns/op	    7909 B/op	      28 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-9-12     	   10000	    157672 ns/op	    8181 B/op	      30 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-10-12    	   10000	    168863 ns/op	    8437 B/op	      32 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-11-12    	   10000	    167745 ns/op	    8725 B/op	      34 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W4-12-12    	   10000	    177620 ns/op	    8965 B/op	      36 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-1-12        	    1000	   1190968 ns/op	    5664 B/op	      15 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-2-12        	    2000	   1023288 ns/op	    5920 B/op	      17 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-3-12        	    2000	    777303 ns/op	    6192 B/op	      19 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-4-12        	    2000	    671296 ns/op	    6448 B/op	      21 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-5-12        	    2000	    551805 ns/op	    6720 B/op	      23 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-6-12        	    3000	    532176 ns/op	    6976 B/op	      25 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-7-12        	    3000	    493157 ns/op	    7248 B/op	      27 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-8-12        	    3000	    501420 ns/op	    7504 B/op	      29 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-9-12        	    3000	    491974 ns/op	    7776 B/op	      31 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-10-12       	    5000	    432767 ns/op	    8032 B/op	      33 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-11-12       	    3000	    421337 ns/op	    8320 B/op	      35 allocs/op
    BenchmarkWOTSP/GenPublicKey-W16-12-12       	    3000	    407954 ns/op	    8560 B/op	      37 allocs/op
    BenchmarkWOTSP/Sign-W16-1-12                	    3000	    593656 ns/op	    5779 B/op	      17 allocs/op
    BenchmarkWOTSP/Sign-W16-2-12                	    2000	    514728 ns/op	    6035 B/op	      19 allocs/op
    BenchmarkWOTSP/Sign-W16-3-12                	    3000	    420184 ns/op	    6307 B/op	      21 allocs/op
    BenchmarkWOTSP/Sign-W16-4-12                	    5000	    381084 ns/op	    6563 B/op	      23 allocs/op
    BenchmarkWOTSP/Sign-W16-5-12                	    3000	    370102 ns/op	    6835 B/op	      25 allocs/op
    BenchmarkWOTSP/Sign-W16-6-12                	    5000	    338943 ns/op	    7091 B/op	      27 allocs/op
    BenchmarkWOTSP/Sign-W16-7-12                	    5000	    318898 ns/op	    7363 B/op	      29 allocs/op
    BenchmarkWOTSP/Sign-W16-8-12                	    5000	    323298 ns/op	    7619 B/op	      31 allocs/op
    BenchmarkWOTSP/Sign-W16-9-12                	    5000	    319790 ns/op	    7891 B/op	      33 allocs/op
    BenchmarkWOTSP/Sign-W16-10-12               	    5000	    304686 ns/op	    8147 B/op	      35 allocs/op
    BenchmarkWOTSP/Sign-W16-11-12               	    5000	    311558 ns/op	    8435 B/op	      37 allocs/op
    BenchmarkWOTSP/Sign-W16-12-12               	    3000	    387059 ns/op	    8675 B/op	      39 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-1-12    	    2000	    618551 ns/op	    3315 B/op	      14 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-2-12    	    2000	    671003 ns/op	    3571 B/op	      16 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-3-12    	    3000	    458555 ns/op	    3843 B/op	      18 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-4-12    	    3000	    424912 ns/op	    4099 B/op	      20 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-5-12    	    5000	    347741 ns/op	    4371 B/op	      22 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-6-12    	    5000	    307307 ns/op	    4627 B/op	      24 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-7-12    	    5000	    292079 ns/op	    4899 B/op	      26 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-8-12    	    5000	    297520 ns/op	    5155 B/op	      28 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-9-12    	    5000	    277718 ns/op	    5427 B/op	      30 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-10-12   	    5000	    290740 ns/op	    5683 B/op	      32 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-11-12   	    5000	    269477 ns/op	    5971 B/op	      34 allocs/op
    BenchmarkWOTSP/PublicKeyFromSig-W16-12-12   	    5000	    304969 ns/op	    6211 B/op	      36 allocs/op
    ```
</details>


## References
[1] Hülsing, Andreas. "W-OTS+–shorter signatures for hash-based signature schemes." International Conference on Cryptology in Africa. Springer, Berlin, Heidelberg, 2013.

[2] Hülsing, Andreas, Joost Rijneveld, and Fang Song. "Mitigating multi-target attacks in hash-based signatures." Public-Key Cryptography–PKC 2016. Springer, Berlin, Heidelberg, 2016. 387-416.