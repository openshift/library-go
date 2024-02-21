OUTPUT ?= CSV
CLUSTER_ENV ?= baremetal

GO_SRC := main.go

EXECUTABLE := commatrix

.DEFAULT_GOAL := run

build:
	go build -o $(EXECUTABLE) $(GO_SRC) 

run: build
	./$(EXECUTABLE) -output=$(OUTPUT) -env=$(CLUSTER_ENV)

clean:
	@rm -f $(EXECUTABLE)
