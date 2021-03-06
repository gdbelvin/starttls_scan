/*
Package comment
*/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/gdbelvin/starttls_scan/smtp"
	"log"
	"os"
	"syscall"
)

var (
	nConnectFlag = flag.Int("concurrent", 100, "Number of concurrent connections")
	portFlag     = flag.String("port", "25", "Destination port")
	databaseFlag = flag.String("database", "", "Configuration string for the database. Formatted as METHOD:CONFIG. (e.g., sqlite3:/path/to/database.db")
)

type scanInputType int

const (
	DOMAIN scanInputType = 1
	MXADDR scanInputType = 2
)

type scanConfig struct {
	index         int           // The input index of this entry
	scanInputType scanInputType // The type of input record
	value         string        // The input string value
}

type ScanResult struct {
	Address             string // IPv4/6 address
	Timestamp           int64  // UNIX timestamp (nanoseconds)
	ConnectionSuceeded  bool   // Did the TCP connection succeed?
	Error	            string
	Smtp		    smtp.SmtpConnectionState
}

// Before running main, parse flags and load message data, if applicable
func mainInit() {
	flag.Parse()

	if *databaseFlag == "" {
		log.Fatalln("You must specify a database configuration (-database)")
	}

	// Increase file descriptor limit
	rlimit := syscall.Rlimit{Max: uint64(*nConnectFlag + 4), Cur: uint64(*nConnectFlag + 4)}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		log.Fatalln(fmt.Sprintf("Error setting rlimit: %s", err))
	}
}

func output(resultChan chan ScanResult, doneChan chan int, db *Database) {
	for result := range resultChan {
		err := db.InsertResult(&result)
		if err != nil {
			log.Printf("Failed to insert row [%v] into database: %v", result, err)
		}
	}
	doneChan <- 1
}

func main() {
	mainInit()
	dbtype, dbpath, err := parseDbConfig(*databaseFlag)
	if err != nil {
		log.Fatalf("Error opening db: %v\n", err)
	}
	db, err := initDb(dbtype, dbpath)
	if err != nil {
		log.Fatalf("Error opening db: %v\n", err)
	}
	defer db.Close()

	taskChan := make(chan scanConfig, *nConnectFlag)   // Channel for tasking
	resultChan := make(chan ScanResult, *nConnectFlag) // Results written here for output
	doneChan := make(chan int, *nConnectFlag)          // let goroutines signal completion

	// Start goroutines
	go output(resultChan, doneChan, db)
	for i := 0; i < *nConnectFlag; i++ {
		go scanner(taskChan, resultChan, doneChan)
	}
	fmt.Println("Ready to go")
	// Read addresses from stdin and pass to grabbers
	scanner := bufio.NewScanner(os.Stdin)
	index := 0
	for scanner.Scan() {
		fmt.Println(">> ", scanner.Text())
		taskChan <- scanConfig{index: index, scanInputType: MXADDR, value: scanner.Text()}
		index += 1
	}
	close(taskChan)

	// Wait for completion
	for i := 0; i < *nConnectFlag; i++ {
		<-doneChan
	}
	close(resultChan)
	<-doneChan

	log.Println("Scanning complete!")
}
