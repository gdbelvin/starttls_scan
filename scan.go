package main

import "fmt"
import "net/smtp"

func connect(dst string) {
    // Connect to a mail server and print the connection object.
    client, err  := smtp.Dial(dst);
    if err != nil{
        panic(err)
    }

    fmt.Println("client: ", client);
    fmt.Println("server:", client.serverName);
    fmt.Println("using tls: ", client.tls);
}

func main() {
    connect("localhost:25");
    fmt.Println("hello world");
}

