IMAGE_NAME = port_scanner
NETWORK_NAME = csce413_assignment2_vulnerable_network

build: 
	docker build -t $(IMAGE_NAME) .

run:
	docker run --network $(NETWORK_NAME) --rm $(IMAGE_NAME) $(args)

clean:
	docker rmi $(IMAGE_NAME)
