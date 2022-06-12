# demo

A simple echo server to demonstrate kTLS.

## Usage

run server:
```
$ ../gradlew :demo:run
```

client:
```
$ openssl s_client -connect localhost:9090
foo
foo
```

test sendfile:
```
$ openssl s_client -connect localhost:9090
lorem-ipsum
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
```
