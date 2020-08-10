package MAPL_engine

import(
	"bufio"
	"fmt"
	"os"
)

func ReadBinaryFile(filename string) ([]byte, error) {

	file, err := os.Open(filename)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// calculate the bytes size
	var size int64 = info.Size()
	bytes := make([]byte, size)

	// read into buffer
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(bytes)
	return bytes, err
}
