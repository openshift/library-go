FORMAT ?= csv
CLUSTER_ENV ?= baremetal
DEST_DIR ?= .

GO_SRC := cmd/main.go

EXECUTABLE := commatrix

.DEFAULT_GOAL := run

build:
	go build -o $(EXECUTABLE) $(GO_SRC) 

generate: build
	mkdir -p $(DEST_DIR)/communication-matrix
	./$(EXECUTABLE) -format=$(FORMAT) -env=$(CLUSTER_ENV) -destDir=$(DEST_DIR)/communication-matrix

clean:
	@rm -f $(EXECUTABLE)
