# Simple test of bearssl server

## Description

This generates a simple ssl echo server using brssl.

## Running the example

In a terminal start the server (it executes on port 1234):

```
./test-ssl-endpoint
```

You can run a client in another terminal with openssl or brssl:

```
openssl s_client -connect localhost:1234 -CAfile server.cert
```

OR

```
./brssl client localhost:1234 -CA server.cert -nosni
```

If you want to run another test server with the same certificates,
you also get the choice between openssl and brssl:

```
openssl s_server -accept 1234 -cert server.cert -key server.key 
```

OR 

```
brssl server -cert server.cert -p 1234 -key server.key
```


## Configuration

The `config` folder contains the server key and certificate.

They were generated with:

```
openssl req  -nodes -new -x509  -keyout server.key -out server.cert
```

I then used brssl to generate the equivalent C code with:

```
brssl skey -C server.key
brssl chain server.cert
```
and copy-pasted it inside the C files.

