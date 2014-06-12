package main

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/coopernurse/gorp"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"strings"
)

type Database struct {
	dbmap *gorp.DbMap
}

func parseDbConfig(config string) (string, string, error) {
	configParams := strings.Split(config, ":")
	if len(configParams) != 2 {
		return "", "", errors.New("Invalid config string")
	}
	dbtype, dbconfig := configParams[0], configParams[1]
	return dbtype, dbconfig, nil
}

func dialectAndDriver(dbtype string) (gorp.Dialect, string) {
        switch dbtype {
        case "sqlite":
                return gorp.SqliteDialect{}, "sqlite3"
        }
        panic("invalid dbtype.")
}

func connect(driver string, path string) *sql.DB {
        db, err := sql.Open(driver, path)
        if err != nil {
                panic("Error connecting to db: " + err.Error())
        }
        return db
}

func newDbMap(dbtype string, dbpath string) *gorp.DbMap {
	dialect, driver := dialectAndDriver(dbtype)
	dbmap := &gorp.DbMap{Db: connect(driver, dbpath), Dialect: dialect}
        return dbmap
}

func initDb(dbtype string, dbpath string) (*Database, error) {
	dbmap := newDbMap(dbtype, dbpath)
	dbmap.AddTableWithName(ScanResult{}, "scan_results").SetKeys(true, "Id")

	err := dbmap.CreateTablesIfNotExists()
	if err != nil {
		return nil, fmt.Errorf("Failed to create database tables: %v", err)
	}

	return &Database{dbmap: dbmap}, nil
}

func (db *Database) Close() {
	db.dbmap.Db.Close()
}

func (db *Database) InsertResult(result *ScanResult) {
	err := db.dbmap.Insert(result)
	if err != nil {
		log.Println(fmt.Sprintf("ERROR: Failed to insert row [%v] into database", *result), err)
	}
}
