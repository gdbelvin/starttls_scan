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

type Certificate struct {
	cert []byte
}

type scanResult struct {
	Id                  int64  `db:"id"`
	Address             string // IPv4/6 address
	Timestamp           int64  // UNIX timestamp (nanoseconds)
	ConnectionSuceeded  bool   // Did the TCP connection succeed?
	SmtpConnectionState smtp.SmtpConnectionState
	Error               error
}

func (r *scanResult) HasSMTP() bool {
	return r.SmtpConnectionState.ExtSTARTTLS
}
func (r *scanResult) TlsSucceeded() bool {
	return r.SmtpConnectionState.Tls
}
func (r *scanResult) TlsVersion() uint16 {
	return r.SmtpConnectionState.TlsConnectionState.Version
}
func (r *scanResult) CipherSuite() uint16 {
	return r.SmtpConnectionState.TlsConnectionState.CipherSuite
}

// Before running main, parse flags and load message data, if applicable
func init() {
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

func output(resultChan chan scanResult, doneChan chan int, db *Database) {
	for result := range resultChan {
		db.InsertResult(&result)
	}
	doneChan <- 1
}

func main() {
	db := initDb(*databaseFlag)
	defer db.Close()

	taskChan := make(chan scanConfig, *nConnectFlag)   // Channel for tasking
	resultChan := make(chan scanResult, *nConnectFlag) // Results written here for output
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
		fmt.Println(">> %v", scanner.Text())
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
