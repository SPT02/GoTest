package main

import (
	"database/sql"
	"net/http"
	"time"
	swaggerFiles "github.com/swaggo/files"
    ginSwagger "github.com/swaggo/gin-swagger"
    _ "GoTest/docs"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/dgrijalva/jwt-go"
	"github.com/SPT02/GoTest/database"
	"github.com/SPT02/GoTest/migrations"
	"github.com/SPT02/GoTest/models"
)

var (
	DB *sql.DB
)

func main() {
	// Initialize DB connection
	var err error
	DB, err = sql.Open("mysql", "root:password@tcp(localhost:3306)/gotest")
	if err != nil {
		panic("failed to connect database")
	}
	defer DB.Close()

	// Ensure DB connection is valid
	err = DB.Ping()
	if err != nil {
		panic("failed to ping database")
	}

	// Run migrations
	err = migrations.Migrate(DB)
	if err != nil {
		panic(err)
	}

	// Create a Gin router
	r := gin.Default()
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.POST("/register", createUser)
	r.POST("/login", loginUser)

	// Apply AuthMiddleware to routes that require authentication
	authGroup := r.Group("/user")
	authGroup.Use(AuthMiddleware())

	// Define routes with authentication
	authGroup.GET("/me", getCurrentUser)
	authGroup.PATCH("/me", updateUser)
	authGroup.POST("/accounting/transfer", transferCredit)
	authGroup.GET("/accounting/transfer-list", getTransferList)

	// Run the server
	r.Run(":8080")
}

// AuthMiddleware function to authenticate user via JWT token
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from header
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Validate and parse JWT token
		userID, err := parseJWTToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set userID in context for later use in handlers
		c.Set("userID", userID)

		// Continue down the middleware chain
		c.Next()
	}
}

// Function to parse and validate JWT token
func parseJWTToken(tokenString string) (int, error) {
    // Example token format: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwLCJleHAiOjE2MjQ2NTI1MzB9.X5DkRjKF2l0JF5cFFRYTNFGkRzSlSWvvgxBrklT6Q6M"
    // In a real application, validate and decode the token properly
    const bearerPrefix = "Bearer "
    if !strings.HasPrefix(tokenString, bearerPrefix) {
        return 0, fmt.Errorf("invalid token format")
    }

    token := tokenString[len(bearerPrefix):]

    // Parse and validate the JWT token
    claims := jwt.MapClaims{}
    _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
        // Verify signing method and return key
        return []byte("your_secret_key"), nil
    })
    if err != nil {
        return 0, err
    }

    // Extract userID from JWT claims
    userID, ok := claims["user_id"].(float64)
    if !ok {
        return 0, fmt.Errorf("user_id not found in token claims")
    }

    return int(userID), nil
}

// @Summary Create a new user
// @Description Create a new user with the provided details
// @Tags users
// @Accept json
// @Produce json
// @Param user body User true "User object to be created"
// @Success 201 {object} User
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /users [post]
func createUser(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check for empty or null values
	if user.Username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is required"})
		return
	}
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
		return
	}
	if user.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name is required"})
		return
	}
	if user.Account_no == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Account_no is required"})
		return
	}
	if len(user.Account_no) != 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Account_no must be 10 digits"})
		return
	}

	// Insert the new user into the database with initial credit
	result, err := DB.Exec("INSERT INTO users (username, password, name, account_no, credit) VALUES (?, ?, ?, ?, ?)",
		user.Username, user.Password, user.Name, user.Account_no, 1000.0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	userID, _ := result.LastInsertId()
	user.ID = int(userID)

	c.JSON(http.StatusCreated, user)
}

// @Summary Login user
// @Description Authenticate user with username and password
// @Tags users
// @Accept json
// @Produce json
// @Param login body LoginCredentials true "User credentials for login"
// @Success 200 {object} gin.H{"token":string,"user":User}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /login [post]
func loginUser(c *gin.Context) {
	var login models.User
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	err := DB.QueryRow("SELECT id, username, name, account_no, credit FROM users WHERE username = ? AND password = ?",
		login.Username, login.Password).Scan(&user.ID, &user.Username, &user.Name, &user.Account_no, &user.Credit)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Generate JWT token
	token, err := generateJWTToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT token"})
		return
	}

	// Return JWT token and user data
	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

// Function to generate JWT token
func generateJWTToken(userID int) (string, error) {
	// Define the expiration time for the token (e.g., 1 hour)
	expirationTime := time.Now().Add(1 * time.Hour)

	// Create the JWT claims, which include the user ID and expiry time
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
		IssuedAt:  time.Now().Unix(),
		Subject:   string(userID),
	}

	// Sign the token with a secret key
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("your_secret_key")) // Replace with your actual secret key
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// @Summary Get current user ID
// @Description Retrieves the ID of the currently authenticated user from JWT token
// @Tags auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {integer} integer
// @Failure 401 {object} ErrorResponse
// @Router /user/me [get]
func getCurrentUserId(c *gin.Context) (int, error) {
    // Extract user claims from JWT
    claims := jwt.ExtractClaims(c)

    // Retrieve userID from claims (assuming it's stored as int in claims)
    userIDFloat, ok := claims["id"].(float64)
    if !ok {
        return 0, fmt.Errorf("userID not found in claims")
    }
    userID := int(userIDFloat)

    return userID, nil
}

// @Summary Get current user details
// @Description Retrieves details of the currently authenticated user
// @Tags users
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} User
// @Failure 401 {object} ErrorResponse
// @Router /user/me [get]
func getCurrentUser(c *gin.Context) {
    // Extract userID from JWT claims
    userID, err := getCurrentUserId(c)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Query user details from database
    var user models.User
    err = DB.QueryRow("SELECT id, username, name, account_no, credit FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Username, &user.Name, &user.Account_no, &user.Credit)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, user)
}

// @Summary Update current user details
// @Description Updates details (name, account_no) of the currently authenticated user
// @Tags users
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param user body User true "User object containing updated details"
// @Success 200 {object} User
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /user/me [patch]
func updateUser(c *gin.Context) {
    // Extract userID from JWT claims
    userID, err := getCurrentUserId(c)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Bind JSON request body to update model
    var update models.User
    if err := c.ShouldBindJSON(&update); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Check for empty or null values
    if update.Password == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
        return
    }
    if update.Name == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Name is required"})
        return
    }
    if update.Account_no == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Account_no is required"})
        return
    }
    if len(update.Account_no) != 10 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Account_no must be 10 digits"})
        return
    }

    // Update the user data in the database
    _, err = DB.Exec("UPDATE users SET password = ?, name = ?, account_no = ? WHERE id = ?",
        update.Password, update.Name, update.Account_no, userID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.Status(http.StatusOK)
}

// @Summary Transfer credit between user accounts
// @Description Transfers a specified amount of credit from the authenticated user's account to another user's account
// @Tags accounting
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param transferRequest body TransferRequest true "Transfer details"
// @Success 200 {object} gin.H{"message": string}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /user/accounting/transfer [post]
func transferCredit(c *gin.Context) {
	// Extract userID from JWT claims
	userID, err := getCurrentUserId(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Bind JSON request body to transferRequest struct
	var transferRequest struct {
		ToAccountNo string  `json:"to_account_no"`
		Amount      float64 `json:"amount"`
	}
	if err := c.ShouldBindJSON(&transferRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate account_no format (must be 10 digits)
	if len(transferRequest.ToAccountNo) != 10 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Account_no must be 10 digits"})
		return
	}

	// Validate amount to be greater than zero
	if transferRequest.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Amount must be greater than zero"})
		return
	}

	// Get sender's account_no from the authenticated user
	var senderAccountNo string
	err = DB.QueryRow("SELECT account_no FROM users WHERE id = ?", userID).Scan(&senderAccountNo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sender's account_no"})
		return
	}

	// Begin transaction to ensure atomicity
	tx, err := DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin transaction"})
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
	}()

	// Get receiver's user ID for to_account_no
	toUserID, err := getUserIDByAccountNo(transferRequest.ToAccountNo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "To account not found"})
		return
	}

	// Deduct credit from sender's account
	_, err = tx.Exec("UPDATE users SET credit = credit - ? WHERE id = ? AND credit >= ?", transferRequest.Amount, userID, transferRequest.Amount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to deduct credit from source account"})
		return
	}

	// Add credit to receiver's account
	_, err = tx.Exec("UPDATE users SET credit = credit + ? WHERE id = ?", transferRequest.Amount, toUserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add credit to destination account"})
		return
	}

	// Insert into TransferHistory
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	_, err = tx.Exec("INSERT INTO TransferHistory (timestamp, Sender_UserId, Receiver_UserId, amount) VALUES (?, ?, ?, ?)",
		currentTime, userID, toUserID, transferRequest.Amount)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record transfer in TransferHistory"})
		return
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Credit transfer successful"})
}

// @Summary Get list of transfer history
// @Description Retrieves a list of transfer history for the authenticated user within the specified date range
// @Tags accounting
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param start_date query string false "Start date (YYYY-MM-DD) to filter transfers"
// @Param end_date query string false "End date (YYYY-MM-DD) to filter transfers"
// @Success 200 {array} TransferHistory
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /user/accounting/transfer-list [get]
func getTransferList(c *gin.Context) {
	// Extract userID from context
	userID := c.MustGet("userID").(int)

	startDateStr := c.Query("start_date")
	endDateStr := c.Query("end_date")

	// Parse start_date and end_date query parameters
	var startDate, endDate time.Time
	var err error
	if startDateStr != "" {
		startDate, err = time.Parse("2006-01-02", startDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid start_date format (expected: YYYY-MM-DD)"})
			return
		}
	}
	if endDateStr != "" {
		endDate, err = time.Parse("2006-01-02", endDateStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid end_date format (expected: YYYY-MM-DD)"})
			return
		}
	}

	// Prepare SQL query based on provided filters
	var rows *sql.Rows
	if startDateStr != "" && endDateStr != "" {
		rows, err = DB.Query(`
			SELECT th.id, th.timestamp, th.Sender_UserId, u1.account_no as Sender_UserAccountNo, 
				   th.Receiver_UserId, u2.account_no as Receiver_UserAccountNo, th.amount 
			FROM TransferHistory th
			INNER JOIN users u1 ON th.Sender_UserId = u1.id
			INNER JOIN users u2 ON th.Receiver_UserId = u2.id
			WHERE (th.Sender_UserId = ? OR th.Receiver_UserId = ?) AND th.timestamp >= ? AND th.timestamp <= ?`,
			userID, userID, startDate, endDate)
	} else if startDateStr != "" {
		rows, err = DB.Query(`
			SELECT th.id, th.timestamp, th.Sender_UserId, u1.account_no as Sender_UserAccountNo, 
				   th.Receiver_UserId, u2.account_no as Receiver_UserAccountNo, th.amount 
			FROM TransferHistory th
			INNER JOIN users u1 ON th.Sender_UserId = u1.id
			INNER JOIN users u2 ON th.Receiver_UserId = u2.id
			WHERE (th.Sender_UserId = ? OR th.Receiver_UserId = ?) AND th.timestamp >= ?`,
			userID, userID, startDate)
	} else if endDateStr != "" {
		rows, err = DB.Query(`
			SELECT th.id, th.timestamp, th.Sender_UserId, u1.account_no as Sender_UserAccountNo, 
				   th.Receiver_UserId, u2.account_no as Receiver_UserAccountNo, th.amount 
			FROM TransferHistory th
			INNER JOIN users u1 ON th.Sender_UserId = u1.id
			INNER JOIN users u2 ON th.Receiver_UserId = u2.id
			WHERE (th.Sender_UserId = ? OR th.Receiver_UserId = ?) AND th.timestamp <= ?`,
			userID, userID, endDate)
	} else {
		rows, err = DB.Query(`
			SELECT th.id, th.timestamp, th.Sender_UserId, u1.account_no as Sender_UserAccountNo, 
				   th.Receiver_UserId, u2.account_no as Receiver_UserAccountNo, th.amount 
			FROM TransferHistory th
			INNER JOIN users u1 ON th.Sender_UserId = u1.id
			INNER JOIN users u2 ON th.Receiver_UserId = u2.id
			WHERE th.Sender_UserId = ? OR th.Receiver_UserId = ?`,
			userID, userID)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	// Prepare result slice
	var transfers []gin.H
	for rows.Next() {
		var transfer struct {
			ID                  int       `json:"id"`
			Timestamp           time.Time `json:"timestamp"`
			SenderUserID        int       `json:"sender_user_id"`
			SenderUserAccountNo string    `json:"sender_useraccountno"`
			ReceiverUserID      int       `json:"receiver_user_id"`
			ReceiverUserAccountNo string    `json:"receiver_useraccountno"`
			Amount              float64   `json:"amount"`
		}
		err := rows.Scan(&transfer.ID, &transfer.Timestamp, &transfer.SenderUserID, &transfer.SenderUserAccountNo, &transfer.ReceiverUserID, &transfer.ReceiverUserAccountNo, &transfer.Amount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		transfers = append(transfers, gin.H{
			"id":                     transfer.ID,
			"timestamp":              transfer.Timestamp.Format("2006-01-02 15:04:05"),
			"sender_user_id":         transfer.SenderUserID,
			"sender_useraccountno":   transfer.SenderUserAccountNo,
			"receiver_user_id":       transfer.ReceiverUserID,
			"receiver_useraccountno": transfer.ReceiverUserAccountNo,
			"amount":                 transfer.Amount,
		})
	}

	c.JSON(http.StatusOK, transfers)
}

