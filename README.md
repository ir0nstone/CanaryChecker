### CanaryChecker
Essentially bruteforces offsets using the '%x$lx' format string attack. Any values ending in 00 are saved. It then repeats to check any changed values to calculate the correct canary.

It will need to be changed depending on the binary you are using it on.
