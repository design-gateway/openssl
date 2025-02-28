#-----------------------------------------------------------------------
# script for build custom OpenSSL to support DGTLS10GC demo
#-----------------------------------------------------------------------
sudo make clean
sudo make distclean
./Configure --prefix=/home/${USER}/tool/openssl --debug -Werror --strict-warnings no-tests no-ssl2 no-dtls no-dtls1 no-srp no-apps no-docs no-ocsp no-quic
make
sudo make install_sw