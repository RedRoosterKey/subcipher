# vigcipher
Simple terminal to apply an insecure Vigenère cipher to STDIN and send results to STDOUT

https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

# How to build
Go into the Release directory and run the following command:
```shell
make all && make test
```
This will create a program called vigcipher and execute test.sh in the scripts directory.
If all the tests pass, you should be good to go.  A good start would be to read the help by running:
```shell
./vigcipher --help
```
