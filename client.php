<?php

$clientPrivateKey = openssl_pkey_get_private('file://clientpk.pem');

$clientPublicKey = openssl_pkey_get_public("file://clientpuk.pem");

$serverAddress = "127.0.0.1"; // Bind to all available network interfaces
$serverPort = 6262; // Choose a port number

$clientSocket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_connect($clientSocket, $serverAddress, $serverPort);

$challenge = socket_read($clientSocket, 1024);

openssl_sign($challenge, $signature, $clientPrivateKey, OPENSSL_ALGO_SHA256);
socket_write($clientSocket, $signature, strlen($signature));


$authenticationResult = socket_read($clientSocket, 1024);
echo $authenticationResult;

socket_close($clientSocket);
