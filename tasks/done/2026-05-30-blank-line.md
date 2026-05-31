`hermod rx` prints out one extra blank line. remove. this is wrong when we send text, we should add \n at the end of the text to make the console output correct. inn all other cases we do not add extra visual \n.

example 1.

```
./hermod rx 15879-many-gecko-crazy
Establishing P2P connection...
receiving 100% |█████████████████████████████████████████████████████████████████████████████████████████████| (213/213 MB, 54 MB/s)        

Saved to code-1.120.0-1778619100.el8.x86_64(1).rpm
```

example 2.

```
./hermod rx 6826-sip-prude-stack
Establishing P2P connection...
hei

```