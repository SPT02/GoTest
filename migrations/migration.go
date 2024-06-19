package migrations

import (
	"database/sql"
	"strings"
)

func Migrate(db *sql.DB) error {
	// Split the SQL statements using ';' as the delimiter
	sqlStatements := `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            password VARCHAR(100) NOT NULL,
            name VARCHAR(100) NOT NULL,
            account_no VARCHAR(50) NOT NULL,
            credit DECIMAL(10,2) NOT NULL
        );
		CREATE TABLE IF NOT EXISTS TransferHistory (
    		id INT AUTO_INCREMENT PRIMARY KEY,
    		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    		Sender_UserId INT NOT NULL,
    		Sender_UserAccountNo VARCHAR(50) NOT NULL,
    		Receiver_UserId INT NOT NULL,
    		Receiver_UserAccountNo VARCHAR(50) NOT NULL,
    		amount DECIMAL(10, 2) NOT NULL
		);
    `
	statements := strings.Split(sqlStatements, ";")

	// Execute each SQL statement individually
	for _, statement := range statements {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}

		_, err := db.Exec(statement)
		if err != nil {
			return err
		}
	}

	return nil
}
