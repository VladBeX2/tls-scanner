all:

build:
	docker build -t tls-scanner .

run:
	docker run --rm tls-scanner