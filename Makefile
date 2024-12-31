.PHONY: run-client run-server

CLIENT_DIR=./client
SERVER_DIR=./server

AIR=air

run-client:
	@echo "Starting client with air..."
	cd $(CLIENT_DIR) && $(AIR)

# Run server with air
run-server:
	@echo "Starting server with air..."
	cd $(SERVER_DIR) && $(AIR)
