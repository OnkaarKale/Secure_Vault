package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "./data/securevault.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, title, encrypted_payload FROM vault_entries")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Println("\n--- RAW DATABASE INSPECTION ---")
	for rows.Next() {
		var id, title string
		var payload []byte
		if err := rows.Scan(&id, &title, &payload); err != nil {
			log.Fatal(err)
		}
		previewLen := 30
		if len(payload) < previewLen {
			previewLen = len(payload)
		}
		fmt.Printf("Entry ID        : %s\nTitle           : %s\nStored Payload  : %x...\n-----------------------------------\n", id, title, payload[:previewLen])
	}
}
