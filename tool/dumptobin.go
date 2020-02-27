package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
)

func main() {
	err := run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	os.Exit(0)
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("need path")
	}
	basePath := os.Args[1]
	path := basePath + ".txt"
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := os.Create(path + ".hexdump")
	if err != nil {
		return err
	}
	defer w.Close()

	dump := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		if !strings.Contains(scanner.Text(), "|") {
			return fmt.Errorf("not a hex.dump")
		}
		if !strings.Contains(scanner.Text(), " ") {
			return fmt.Errorf("not a hex.dump")
		}
		line := scanner.Text()
		line = line[strings.Index(scanner.Text(), " ")+1 : strings.Index(scanner.Text(), "|")]
		line = strings.ReplaceAll(line, " ", "")
		dump += line
	}

	fmt.Println(dump)
	data, err := hex.DecodeString(dump)
	if err != nil {
		return errors.Wrap(err, "decode")
	}

	_, err = w.Write(data)
	if err != nil {
		return errors.Wrap(err, "write")
	}
	if err := scanner.Err(); err != nil {
		return errors.Wrap(err, "scanner")
	}
	return nil
}
