# WNFInjector

This was a simple Golang learning exercise.

It utilizes "WNF Injection" to inject and execute a PIC payload, usually generated using Donut.

The recycled technique scans for the WNF table & handlers of the PE process and overwrites a callback in a handler structure.
