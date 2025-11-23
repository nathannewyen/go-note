package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Task represents a single task/note item
type Task struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Completed   bool      `json:"completed"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	UserID      int       `json:"user_id"`
}

// User represents a user account (internal use, includes password)
type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
}

// UserResponse represents user data for API responses (excludes password)
type UserResponse struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// RegisterRequest represents the registration payload
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents the login payload
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents the login response with JWT token
type LoginResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before writing it
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Database connection will be stored globally for simplicity
var database *sql.DB

// JWT secret key - In production, use environment variable
var jwtSecretKey = []byte("your-secret-key-change-this-in-production")

func main() {
	// Initialize database connection
	var err error
	database, err = sql.Open("sqlite", "notes.db")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Close()

	// Create users table if it doesn't exist
	createUsersTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = database.Exec(createUsersTableQuery)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}

	// Create tasks table if it doesn't exist
	createTasksTableQuery := `
	CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT,
		completed BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		user_id INTEGER NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);`

	_, err = database.Exec(createTasksTableQuery)
	if err != nil {
		log.Fatal("Failed to create tasks table:", err)
	}

	// Set up HTTP routes
	// We're using the standard library's http.ServeMux for routing
	mux := http.NewServeMux()

	// Auth routes (public - no authentication required)
	mux.HandleFunc("/auth/register", handleRegister)
	mux.HandleFunc("/auth/login", handleLogin)

	// Task routes (protected - authentication required)
	mux.HandleFunc("/tasks", authMiddleware(handleTasks))
	mux.HandleFunc("/tasks/", authMiddleware(handleTaskByID))

	// Wrap mux with logging middleware
	loggedMux := loggingMiddleware(mux)

	// Start the HTTP server
	log.Println("Server starting on http://localhost:8080")
	err = http.ListenAndServe(":8080", loggedMux)
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

// generateJWT creates a JWT token for a user
func generateJWT(userID int, email string) (string, error) {
	// Create claims with user information and expiration time
	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Token expires in 24 hours
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret key
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// validateJWT validates a JWT token and returns the claims
func validateJWT(tokenString string) (*JWTClaims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecretKey, nil
	})

	if err != nil {
		return nil, err
	}

	// Extract claims
	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// authMiddleware protects routes by requiring a valid JWT token
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Println("Missing Authorization header")
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Check if it starts with "Bearer "
		if !strings.HasPrefix(authHeader, "Bearer ") {
			log.Println("Invalid Authorization header format")
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Extract token (remove "Bearer " prefix)
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token
		claims, err := validateJWT(tokenString)
		if err != nil {
			log.Printf("Invalid token: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Add user ID to request context so handlers can access it
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "email", claims.Email)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// handleRegister creates a new user account
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.Printf("Invalid JSON in register request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate email and password
	if strings.TrimSpace(req.Email) == "" {
		log.Println("Validation error: Email is required")
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 6 {
		log.Println("Validation error: Password must be at least 6 characters")
		http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Failed to hash password: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Insert user into database
	result, err := database.Exec(
		"INSERT INTO users (email, password) VALUES (?, ?)",
		req.Email, string(hashedPassword),
	)
	if err != nil {
		// Check if email already exists (SQLite unique constraint error)
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			log.Printf("Email already exists: %s", req.Email)
			http.Error(w, "Email already registered", http.StatusConflict)
			return
		}
		log.Printf("Database insert error: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Get the user ID
	userID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get user ID: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Retrieve the created user data
	var userResp UserResponse
	err = database.QueryRow(
		"SELECT id, email, created_at FROM users WHERE id = ?",
		userID,
	).Scan(&userResp.ID, &userResp.Email, &userResp.CreatedAt)

	if err != nil {
		log.Printf("Failed to fetch created user: %v", err)
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Return the created user (password is excluded from UserResponse)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(userResp)
}

// handleLogin authenticates a user and returns a JWT token
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginReq LoginRequest
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		log.Printf("Invalid JSON in login request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Fetch user from database
	var user User
	err = database.QueryRow(
		"SELECT id, email, password, created_at FROM users WHERE email = ?",
		loginReq.Email,
	).Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		log.Printf("Login attempt with non-existent email: %s", loginReq.Email)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	if err != nil {
		log.Printf("Database error during login: %v", err)
		http.Error(w, "Failed to login", http.StatusInternalServerError)
		return
	}

	// Compare password with hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		log.Printf("Invalid password for email: %s", loginReq.Email)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := generateJWT(user.ID, user.Email)
	if err != nil {
		log.Printf("Failed to generate JWT: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Create user response (without password)
	userResp := UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}

	// Return token and user info
	response := LoginResponse{
		Token: token,
		User:  userResp,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// loggingMiddleware logs each HTTP request with method, path, status code, and duration
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record the start time
		startTime := time.Now()

		// Create a wrapped response writer to capture status code
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default status code
		}

		// Call the next handler
		next.ServeHTTP(wrappedWriter, r)

		// Calculate duration
		duration := time.Since(startTime)

		// Log the request details
		// Format: [METHOD] /path - STATUS_CODE STATUS_TEXT (duration)
		statusText := getStatusText(wrappedWriter.statusCode)
		fmt.Printf("%s [%s] %s - %d %s (%v)\n",
			time.Now().Format("2006-01-02 15:04:05"),
			r.Method,
			r.URL.Path,
			wrappedWriter.statusCode,
			statusText,
			duration,
		)
	})
}

// getStatusText returns a text indicator based on status code
func getStatusText(statusCode int) string {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return "SUCCESS"
	case statusCode >= 400 && statusCode < 500:
		return "CLIENT_ERROR"
	case statusCode >= 500:
		return "SERVER_ERROR"
	default:
		return "UNKNOWN"
	}
}

// handleTasks handles requests to /tasks (list all tasks and create new task)
func handleTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getTasks(w, r)
	case http.MethodPost:
		createTask(w, r)
	default:
		// Method not allowed
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTaskByID handles requests to /tasks/:id (get, update, delete specific task)
func handleTaskByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getTask(w, r)
	case http.MethodPut:
		updateTask(w, r)
	case http.MethodDelete:
		deleteTask(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getTasks retrieves all tasks from the database
func getTasks(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user ID from context
	userID := r.Context().Value("userID").(int)

	// Query only tasks belonging to the authenticated user
	rows, err := database.Query(
		"SELECT id, title, description, completed, created_at, updated_at, user_id FROM tasks WHERE user_id = ? ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		http.Error(w, "Failed to fetch tasks", http.StatusInternalServerError)
		log.Println("Database query error:", err)
		return
	}
	defer rows.Close()

	// Slice to hold all tasks
	var tasks []Task

	// Iterate through all rows
	for rows.Next() {
		var task Task
		err := rows.Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt, &task.UserID)
		if err != nil {
			http.Error(w, "Failed to parse tasks", http.StatusInternalServerError)
			log.Println("Row scan error:", err)
			return
		}
		tasks = append(tasks, task)
	}

	// Set a response header to JSON
	w.Header().Set("Content-Type", "application/json")

	// Encode tasks as JSON and send a response
	json.NewEncoder(w).Encode(tasks)
}

// createTask creates a new task from the JSON request body
func createTask(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user ID from context
	userID := r.Context().Value("userID").(int)

	var task Task

	// Decode JSON request body into Task struct
	err := json.NewDecoder(r.Body).Decode(&task)
	if err != nil {
		log.Printf("Invalid JSON in request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate that title is not empty
	if strings.TrimSpace(task.Title) == "" {
		log.Println("Validation error: Task title is required")
		http.Error(w, "Title is required", http.StatusBadRequest)
		return
	}

	// Insert new task into database with user_id
	result, err := database.Exec(
		"INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		task.Title, task.Description, task.Completed, userID,
	)
	if err != nil {
		http.Error(w, "Failed to create task", http.StatusInternalServerError)
		log.Println("Database insert error:", err)
		return
	}

	// Get the ID of the newly created task
	id, err := result.LastInsertId()
	if err != nil {
		log.Printf("Failed to get last insert ID: %v", err)
		http.Error(w, "Failed to get task ID", http.StatusInternalServerError)
		return
	}

	// Retrieve the complete task from the database to get timestamps
	err = database.QueryRow(
		"SELECT id, title, description, completed, created_at, updated_at, user_id FROM tasks WHERE id = ?",
		id,
	).Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt, &task.UserID)

	if err != nil {
		log.Printf("Failed to fetch created task with ID %d: %v", id, err)
		http.Error(w, "Failed to fetch created task", http.StatusInternalServerError)
		return
	}

	// Return the created task with 201 status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(task)
}

// getTask retrieves a single task by ID
func getTask(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user ID from context
	userID := r.Context().Value("userID").(int)

	// Extract ID from the URL path
	id, err := extractID(r.URL.Path)
	if err != nil {
		log.Printf("Invalid task ID in URL path %s: %v", r.URL.Path, err)
		http.Error(w, "Invalid task ID", http.StatusBadRequest)
		return
	}

	// Query task only if it belongs to the authenticated user
	var task Task
	err = database.QueryRow(
		"SELECT id, title, description, completed, created_at, updated_at, user_id FROM tasks WHERE id = ? AND user_id = ?",
		id, userID,
	).Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt, &task.UserID)

	if errors.Is(err, sql.ErrNoRows) {
		log.Printf("Task not found with ID: %d for user ID: %d", id, userID)
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	if err != nil {
		log.Printf("Database query error for task ID %d: %v", id, err)
		http.Error(w, "Failed to fetch task", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// updateTask updates an existing task
func updateTask(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user ID from context
	userID := r.Context().Value("userID").(int)

	// Extract ID from the URL path
	id, err := extractID(r.URL.Path)
	if err != nil {
		log.Printf("Invalid task ID in URL path %s: %v", r.URL.Path, err)
		http.Error(w, "Invalid task ID", http.StatusBadRequest)
		return
	}

	var task Task
	err = json.NewDecoder(r.Body).Decode(&task)
	if err != nil {
		log.Printf("Invalid JSON in request body for task ID %d: %v", id, err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate that title is not empty
	if strings.TrimSpace(task.Title) == "" {
		log.Printf("Validation error: Task title is required for task ID %d", id)
		http.Error(w, "Title is required", http.StatusBadRequest)
		return
	}

	// Update the task in database only if it belongs to the authenticated user
	result, err := database.Exec(
		"UPDATE tasks SET title = ?, description = ?, completed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?",
		task.Title, task.Description, task.Completed, id, userID,
	)
	if err != nil {
		http.Error(w, "Failed to update task", http.StatusInternalServerError)
		log.Println("Database update error:", err)
		return
	}

	// Check if any row was affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Failed to check rows affected for task ID %d: %v", id, err)
		http.Error(w, "Failed to update task", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		log.Printf("Task not found with ID: %d for user ID: %d (update attempt)", id, userID)
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	// Retrieve the updated task
	err = database.QueryRow(
		"SELECT id, title, description, completed, created_at, updated_at, user_id FROM tasks WHERE id = ? AND user_id = ?",
		id, userID,
	).Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt, &task.UserID)

	if err != nil {
		log.Printf("Failed to fetch updated task with ID %d: %v", id, err)
		http.Error(w, "Failed to fetch updated task", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// deleteTask removes a task from the database
func deleteTask(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user ID from context
	userID := r.Context().Value("userID").(int)

	// Extract ID from the URL path
	id, err := extractID(r.URL.Path)
	if err != nil {
		log.Printf("Invalid task ID in URL path %s: %v", r.URL.Path, err)
		http.Error(w, "Invalid task ID", http.StatusBadRequest)
		return
	}

	// Delete task only if it belongs to the authenticated user
	result, err := database.Exec("DELETE FROM tasks WHERE id = ? AND user_id = ?", id, userID)
	if err != nil {
		log.Printf("Database delete error for task ID %d: %v", id, err)
		http.Error(w, "Failed to delete task", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("Failed to check rows affected for task ID %d: %v", id, err)
		http.Error(w, "Failed to delete task", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		log.Printf("Task not found with ID: %d for user ID: %d (delete attempt)", id, userID)
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	// Return success with no content
	w.WriteHeader(http.StatusNoContent)
}

// extractID is a helper function to extract the task ID from the URL path
// For example, "/tasks/123" -> 123
func extractID(path string) (int, error) {
	// Remove the "/tasks/" prefix to get the ID
	parts := strings.Split(strings.TrimPrefix(path, "/tasks/"), "/")
	if len(parts) == 0 {
		return 0, sql.ErrNoRows
	}

	// Convert string ID to integer
	return strconv.Atoi(parts[0])
}
