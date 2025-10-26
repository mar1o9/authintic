#use the makefile for quick dev env
genpkeys:
	genpriv
	genpub

genpriv:
	openssl genpkey -algorithm RSA -out keys/private_key.pem -pkeyopt rsa_keygen_bits:2048

genpub:
	openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
