GEN_OFFSETS_SRC := gen_offsets.c
GEN_OFFSETS_BIN := gen_offsets
OFFSET_HDR := enclave_offsets.h

.PHONY: all clean offset

all: 
	@echo "Nothing to build by default. Use 'make offset' to generate offsets."

# generate offsets header
offset: $(OFFSET_HDR)

$(OFFSET_HDR): $(GEN_OFFSETS_SRC)
	@echo "Generating $(OFFSET_HDR) ..."
	@gcc -O2 $(GEN_OFFSETS_SRC) -o $(GEN_OFFSETS_BIN)
	@./$(GEN_OFFSETS_BIN) > $(OFFSET_HDR)
	@rm ./$(GEN_OFFSETS_BIN)
	@echo "$(OFFSET_HDR) generated."

clean:
	@echo "Cleaning..."
	@rm -f $(GEN_OFFSETS_BIN) $(OFFSET_HDR)
