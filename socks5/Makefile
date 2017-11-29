CC = g++

HEADER = $(shell find ./ -name "*.h")
SRC = $(shell find ./ -name "*.cc" | grep -v socks5.cc | grep -v transfer.cc)

OUTPUT = ./bin
MK_OUTPUT = $(shell test -d $(OUTPUT) || mkdir -p $(OUTPUT))
SOCKS5_BIN = socks5_proxy
TRANSFER_BIN = transfer_proxy

.PHONY:all
all:$(MK_OUTPUT) $(SOCKS5_BIN) $(TRANSFER_BIN)
	@echo "program generate in ./bin/"

$(SOCKS5_BIN):socks5.cc $(SRC) $(HEADER)
	$(CC) -o $(OUTPUT)/$(SOCKS5_BIN) socks5.cc $(SRC) $(HEADER)
	@echo "compling [$<] to [$@] ... done"

$(TRANSFER_BIN):transfer.cc $(SRC) $(HEADER)
	$(CC) -o $(OUTPUT)/$(TRANSFER_BIN) transfer.cc $(SRC) $(HEADER)
	@echo "compling [$<] to [$@] ... done"
	
.PHONY:clean
clean:
	rm -f $(OUTPUT)/*

