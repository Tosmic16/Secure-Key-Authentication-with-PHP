<?php

$serverPrivateKey = openssl_pkey_get_private("serverpk.pem");

$serverAddress = "127.0.0.1"; // Bind to all available network interfaces
$serverPort = 6262; // Choose a port number

$serverSocket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($serverSocket, $serverAddress, $serverPort);
socket_listen($serverSocket);


$clientSocket = socket_accept($serverSocket);
$challenge = bin2hex(random_bytes(16));
$clientPublicKey = openssl_pkey_get_public("file://clientpuk.pem");

socket_write($clientSocket, $challenge, strlen($challenge));

$receivedSignature = socket_read($clientSocket, 1024);
$verified = openssl_verify($challenge, $receivedSignature, $clientPublicKey, OPENSSL_ALGO_SHA256);

if ($verified === 1) {
    socket_write($clientSocket, "Authentication successful!", 25);
} else {
    socket_write($clientSocket, "Authentication failed.", 20);
}

socket_close($clientSocket);
