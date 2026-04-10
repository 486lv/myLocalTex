#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <cstdio>
#include <cstring>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

using namespace std;

const char* CERT_FILE = "C:\\openssl\\bin\\cacert.pem";
const char* KEY_FILE  = "C:\\openssl\\bin\\privatekey.pem";
const int SERVER_PORT = 4433;

int pem_passwd_cb(char* buf, int size, int rwflag, void* userdata)
{
    const char* pwd = (const char*)userdata;
    int len = (int)strlen(pwd);
    if (len > size) len = size;
    memcpy(buf, pwd, len);
    return len;
}

void print_ssl_error(const char* msg)
{
    cout << msg << endl;
    ERR_print_errors_fp(stderr);
}

int main()
{
    WSADATA wsaData;
    SOCKET listenfd = INVALID_SOCKET;
    SOCKET clientfd = INVALID_SOCKET;
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "WSAStartup failed." << endl;
        return -1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD* method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        print_ssl_error("SSL_CTX_new failed.");
        WSACleanup();
        return -1;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    // Ë½Ô¿ÃÜÂë£º123456
    SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)"123456");

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        print_ssl_error("Load certificate failed.");
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        print_ssl_error("Load private key failed.");
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        cout << "Private key does not match certificate." << endl;
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == INVALID_SOCKET)
    {
        cout << "socket failed." << endl;
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        cout << "bind failed." << endl;
        closesocket(listenfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    if (listen(listenfd, 5) == SOCKET_ERROR)
    {
        cout << "listen failed." << endl;
        closesocket(listenfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    cout << "[Server] listening on port " << SERVER_PORT << " ..." << endl;

    clientfd = accept(listenfd, NULL, NULL);
    if (clientfd == INVALID_SOCKET)
    {
        cout << "accept failed." << endl;
        closesocket(listenfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)clientfd);

    if (SSL_accept(ssl) <= 0)
    {
        print_ssl_error("[Server] SSL_accept failed.");
        SSL_free(ssl);
        closesocket(clientfd);
        closesocket(listenfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    cout << "[Server] SSL handshake success." << endl;

    char buf[1024] = {0};
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0)
    {
        buf[n] = '\0';
        cout << "[Server] recv: " << buf << endl;
    }
    else
    {
        cout << "[Server] SSL_read failed or connection closed." << endl;
    }

    const char* reply = "Hello, this is SSL server.";
    SSL_write(ssl, reply, (int)strlen(reply));
    cout << "[Server] reply sent." << endl;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(clientfd);
    closesocket(listenfd);
    SSL_CTX_free(ctx);
    WSACleanup();

    cout << "[Server] finished." << endl;
    system("pause");
    return 0;
}