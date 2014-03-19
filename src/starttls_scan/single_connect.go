package main

import (
    "crypto/tls"
    "fmt"
    "reflect"
    "unsafe"
    "os"
    "net"
    "../smtp"
)

type ConnInfo struct {
    domain string
    hastls bool
    tlssuccess bool
    tcp bool
    conn tls.Conn
}

func readConn(client *smtp.Client) {
    //v := reflect.ValueOf(*client)
    //conn := v.FieldByName("conn")
    //tconn, err := conn.Interface(false).(tls.Conn)

    pointerVal := reflect.ValueOf(client)
    val := reflect.Indirect(pointerVal)

    member := val.FieldByName("conn")
    ptrToY := unsafe.Pointer(member.UnsafeAddr())
    realPtrToY := (**net.Conn)(ptrToY)
    fmt.Println("ptr:   ", realPtrToY)
    fmt.Println("*ptr:  ", *realPtrToY)
    fmt.Println("**ptr: ", **realPtrToY)
    //*realPtrToY = nil // or &Foo{} or whatever
}

func DoConnect(addr string) (ConnInfo, error) {
    ret := ConnInfo{addr, false, false, false, tls.Conn{}}
    serverName := "localhost"

    c, err := smtp.Dial(addr)
    if err != nil {
        return ret, err
    }
    ret.tcp = true
    defer c.Close()
    if err = c.Hello(serverName); err != nil {
        return ret, err
    }
    if ok, _ := c.Extension("STARTTLS"); ok {
        ret.hastls = true
        //config := &tls.Config{ServerName: serverName}
        if err = c.StartTLS(nil); err != nil {
            return ret, err
        }
        ret.tlssuccess = true
        // At this point, convert c.conn 
        readConn(c)
    }
    if err != nil {
        return ret, err
    }
    return ret, c.Quit()
}


func main() {
    dest := os.Args[1]
    fmt.Println("Connecting to: ", dest)
    info, err := DoConnect(dest)
    if err != nil {
       fmt.Println("error: ", err)
    }
    fmt.Println(info)
    fmt.Println("conn: ", info.conn)
}
