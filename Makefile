BUILD_DIR = build
INC_DIR = inc
SRC_DIR = src

all:
	gcc \
		-Wall -Wextra           \
		-O3 -funroll-loops      \
		-march=native			\
		-I$(INC_DIR)			\
		$(SRC_DIR)/*.c		    \
		-o $(BUILD_DIR)/aes 

clean:
	rm -f $(BUILD_DIR)/*