package main

import (
	"fmt"
	"log"
	"os"
)

var logger *log.Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)

func logln(level int, message ...any) {
	if level <= *verbose {
		logger.Println(message...)
	}
}

func logf(level int, format string, v ...any) {
	if level <= *verbose {
		logger.Printf(format, v...)
	}
}

func panicf(format string, v ...any) {
	logger.Panicf(format, v...)
}

func errorf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format, v...)
}
