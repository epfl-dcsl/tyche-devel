#!/bin/bash

openssl s_client -connect localhost:1234 -CAfile config/server.cert
