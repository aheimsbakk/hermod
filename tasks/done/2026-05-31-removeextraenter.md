receiver inserts one extra enter in output for user when viewing stream content. It's correct to do this when sending text. But not for stream.

sender:

```
$ echo test |  ./hermod tx
Transfer code: 40610-blush-vowel-curse
Establishing P2P connection...
sending |.###............................................................................................................................................................................| ( 5 B, 64 kB/s)
Transfer complete.
```

receiver:

```
$  ./hermod rx 40610-blush-vowel-curse
Establishing P2P connection...
test
                                                   <- This is the extra blank line
Receive and verification complete.
```
