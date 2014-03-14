package main

import (
	//"flag"
	"fmt"
	"net/smtp"
	//"os"
	//"syscall"
	//"time"
	//"github.com/dspiteself/gorp"
)

func connect(dst string) {
    // Connect to a mail server and print the connection object.
    client, err  := smtp.Dial(dst);
    if err != nil{
        panic(err)
    }

    fmt.Println("client: ", client);
    //fmt.Println("server:", client.serverName);
    //fmt.Println("using tls: ", client.tls);
}

func main() {
    connect("localhost:25");
    fmt.Println("hello world");
}


