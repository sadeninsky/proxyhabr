BINARY_NAME=main
IMAGE_NAME=proxyhabr

build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ${BINARY_NAME} .
	docker build -t ${IMAGE_NAME} -f Dockerfile.scratch .

run:
	docker run -p 8080:8080 -it ${IMAGE_NAME}

clean:
	go clean
	rm ${BINARY_NAME}
