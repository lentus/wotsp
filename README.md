[![Build Status](https://travis-ci.org/lentus/wotsp.svg?branch=master)](https://travis-ci.org/lentus/wotsp) [![Go Report Card](https://goreportcard.com/badge/github.com/lentus/wotsp)](https://goreportcard.com/report/github.com/lentus/wotsp)

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
i5-6300HQ CPU (4 cores @ 899.964 MHz, ```go test -bench . -benchtime 4s```). 

```
BenchmarkGenPublicKey-4     	    5000	   1156789 ns/op	    5440 B/op	      11 allocs/op
BenchmarkSign-4             	   10000	    563155 ns/op	    5635 B/op	      14 allocs/op
BenchmarkPkFromSig-4        	   10000	    597232 ns/op	    3171 B/op	      11 allocs/op
BenchmarkW4GenPublicKey-4   	   10000	    494899 ns/op	   10560 B/op	      11 allocs/op
BenchmarkW4Sign-4           	   20000	    264257 ns/op	   10949 B/op	      14 allocs/op
BenchmarkW4PkFromSig-4      	   30000	    233671 ns/op	    5925 B/op	      11 allocs/op
```

The branch *concurrent* contains a more optimized version that divides all hash 
chain computations over all available CPU cores (polled with *GOMAXPROCS*). The 
more cores are available, the higher the performance. The benchmarks below were 
obtained on the same system as those above.

```
BenchmarkGenPublicKey-4     	   10000	    416891 ns/op	    6370 B/op	      21 allocs/op
BenchmarkSign-4             	   20000	    270267 ns/op	    6483 B/op	      23 allocs/op
BenchmarkPkFromSig-4        	   20000	    250070 ns/op	    4019 B/op	      20 allocs/op
BenchmarkW4GenPublicKey-4   	   30000	    235407 ns/op	   11552 B/op	      21 allocs/op
BenchmarkW4Sign-4           	   30000	    163759 ns/op	   11797 B/op	      23 allocs/op
BenchmarkW4PkFromSig-4      	   50000	    110329 ns/op	    6773 B/op	      20 allocs/op
```  

## References
[1] Hülsing, Andreas. "W-OTS+–shorter signatures for hash-based signature schemes." International Conference on Cryptology in Africa. Springer, Berlin, Heidelberg, 2013.

[2] Hülsing, Andreas, Joost Rijneveld, and Fang Song. "Mitigating multi-target attacks in hash-based signatures." Public-Key Cryptography–PKC 2016. Springer, Berlin, Heidelberg, 2016. 387-416.