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

const char* CA_FILE   = "C:\\openssl\\bin\\cacert.pem";
const char* SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 4433;

void print_ssl_error(const char* msg)
{
    cout << msg << endl;
    ERR_print_errors_fp(stderr);
}

int main()
{
    WSADATA wsaData;
    SOCKET sockfd = INVALID_SOCKET;
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

    const SSL_METHOD* method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        print_ssl_error("SSL_CTX_new failed.");
        WSACleanup();
        return -1;
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    // 加载信任证书，用于校验服务器证书
    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != 1)
    {
        print_ssl_error("Load CA file failed.");
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET)
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
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        cout << "connect failed." << endl;
        closesocket(sockfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    cout << "[Client] TCP connected." << endl;

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sockfd);

    if (SSL_connect(ssl) <= 0)
    {
        print_ssl_error("[Client] SSL_connect failed.");
        SSL_free(ssl);
        closesocket(sockfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    cout << "[Client] SSL handshake success." << endl;

    // 证书校验
    X509* serverCert = SSL_get_peer_certificate(ssl);
    if (!serverCert)
    {
        cout << "[Client] No server certificate received." << endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sockfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    long verifyResult = SSL_get_verify_result(ssl);
    if (verifyResult != X509_V_OK)
    {
        cout << "[Client] Certificate verify failed: "
             << X509_verify_cert_error_string(verifyResult) << endl;
        X509_free(serverCert);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sockfd);
        SSL_CTX_free(ctx);
        WSACleanup();
        return -1;
    }

    char* subject = X509_NAME_oneline(X509_get_subject_name(serverCert), 0, 0);
    char* issuer  = X509_NAME_oneline(X509_get_issuer_name(serverCert), 0, 0);

    cout << "[Client] Certificate verify success." << endl;
    cout << "[Client] Server Subject: " << subject << endl;
    cout << "[Client] Server Issuer : " << issuer << endl;

    OPENSSL_free(subject);
    OPENSSL_free(issuer);
    X509_free(serverCert);

    const char* msg = "Hello from SSL client.";
    SSL_write(ssl, msg, (int)strlen(msg));
    cout << "[Client] send: " << msg << endl;

    char buf[1024] = {0};
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0)
    {
        buf[n] = '\0';
        cout << "[Client] recv: " << buf << endl;
    }
    else
    {
        cout << "[Client] SSL_read failed or connection closed." << endl;
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sockfd);
    SSL_CTX_free(ctx);
    WSACleanup();

    cout << "[Client] finished." << endl;
    system("pause");
    return 0;
}