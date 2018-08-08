[![Build Status](https://travis-ci.org/lentus/wotsp.svg?branch=concurrent)](https://travis-ci.org/lentus/wotsp) [![Go Report Card](https://goreportcard.com/badge/github.com/lentus/wotsp)](https://goreportcard.com/report/github.com/lentus/wotsp)

# W-OTS+
A Go implementation of the Winternitz OTS (W-OTS+), as described in [RFC8391](https://datatracker.ietf.org/doc/rfc8391/).
This implementation supports Winternitz parameters ```w = 4``` and ```w = 16```, 
which can be selected by setting the ```Mode``` of the ```Opts``` struct to 
```W4``` or ```W16``` respectively (if no mode is provided, ```W16``` is used).

W-OTS+ was first described in [1]. However, the original design is susceptible 
to multi-target attacks. This issue was solved in [2] with WOTS-T. The RFC 
confusingly refers to W-OTS+, despite including the modifications from 
[2] and thus actually describing WOTS-T.      

## Install

```sh
go get -u https://github.com/lentus/wotsp
```

## Performance
The benchmarks below were obtained using a laptop with an Intel(R) Core(TM) 
i5-6300HQ CPU (4 cores @ 899.964 MHz, ```go test -bench . -benchtime 8s```). 

```
BenchmarkGenPublicKey-4               	   10000	   1235117 ns/op	    5664 B/op	      15 allocs/op
BenchmarkSign-4                       	   20000	    623708 ns/op	    5779 B/op	      17 allocs/op
BenchmarkPkFromSig-4                  	   20000	    632719 ns/op	    3315 B/op	      14 allocs/op
BenchmarkW4GenPublicKey-4             	   20000	    556049 ns/op	   10848 B/op	      15 allocs/op
BenchmarkW4Sign-4                     	   50000	    296485 ns/op	   11093 B/op	      17 allocs/op
BenchmarkW4PkFromSig-4                	   50000	    265646 ns/op	    6069 B/op	      14 allocs/op
```

This implementation also supports concurrent hash chains computations. The 
number of used goroutines can be set by setting the ```Concurrent``` variable 
in the Opts struct to a number greater than 0. If it is less than 0, the number 
of goroutines is automatically determined using 
```min(runtime.GOMAXPROCS, runtime.NumCPU)```. By default (if it is 0) one 
goroutine is used. The below benchmarks were obtained using 4 goroutines. 

```
BenchmarkConcurrentGenPublicKey-4     	   30000	    429400 ns/op	    6448 B/op	      21 allocs/op
BenchmarkConcurrentSign-4             	   30000	    469624 ns/op	    6563 B/op	      23 allocs/op
BenchmarkConcurrentPkFromSig-4        	   50000	    273350 ns/op	    4099 B/op	      20 allocs/op
BenchmarkConcurrentW4GenPublicKey-4   	   50000	    253189 ns/op	   11632 B/op	      21 allocs/op
BenchmarkConcurrentW4Sign-4           	  100000	    155405 ns/op	   11877 B/op	      23 allocs/op
BenchmarkConcurrentW4PkFromSig-4      	  100000	    119764 ns/op	    6853 B/op	      20 allocs/op
```  

## References
[1] Hülsing, Andreas. "W-OTS+–shorter signatures for hash-based signature schemes." International Conference on Cryptology in Africa. Springer, Berlin, Heidelberg, 2013.

[2] Hülsing, Andreas, Joost Rijneveld, and Fang Song. "Mitigating multi-target attacks in hash-based signatures." Public-Key Cryptography–PKC 2016. Springer, Berlin, Heidelberg, 2016. 387-416.