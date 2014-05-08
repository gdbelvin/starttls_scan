package main

import (
	"database/sql"
	"fmt"
	"github.com/coopernurse/gorp"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"strings"
)

type Database struct {
	dbmap *gorp.DbMap
}

func initDb(config string) *Database {
	// Connect to database (method:config)
	configParams := strings.Split(config, ":")
	if len(configParams) != 2 {
		log.Fatalln(fmt.Sprintf("Invalid database string: %v", config))
	}
	dbtype, dbconfig := configParams[0], configParams[1]

	log.Printf("Connecting to database type [%v] at [%v]...", dbtype, dbconfig)
	db, err := sql.Open(dbtype, dbconfig)
	if err != nil {
		log.Fatalln(fmt.Sprintf("Failed to connect to database [%v:%v]", dbtype, dbconfig), err)
	}

	dbmap := &gorp.DbMap{Db: db}
	switch dbtype {
	case "sqlite3":
		dbmap.Dialect = gorp.SqliteDialect{}
	default:
		log.Fatalln(fmt.Sprintf("Unknown database type [%v]", dbtype))
	}

	dbmap.AddTableWithName(scanResult{}, "scan_results").SetKeys(true, "Id")

	err = dbmap.CreateTablesIfNotExists()
	if err != nil {
		log.Fatalln("Failed to create database tables", err)
	}

	log.Println("Database initialized")
	return &Database{dbmap: dbmap}
}

func (db *Database) Close() {
	db.dbmap.Db.Close()
}

func (db *Database) InsertResult(result *scanResult) {
	err := db.dbmap.Insert(result)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Failed to insert row [%v] into database", *result), err)
	}
}
