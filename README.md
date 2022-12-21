# MITM

中间人代理，针对经常需要安装证书的环境的忽略服务端证书验证

证书生成：

```shell
openssl genrsa 2048 > key.pem
openssl req -new -x509 -nodes -days 365000 \
   -key key.pem \
   -out cert.pem
```