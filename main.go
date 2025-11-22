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

func main() {
	// Initialize database connection
	var err error
	database, err = sql.Open("sqlite", "notes.db")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Close()

	// Create tasks table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		description TEXT,
		completed BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = database.Exec(createTableQuery)
	if err != nil {
		log.Fatal("Failed to create table:", err)
	}

	// Set up HTTP routes
	// We're using the standard library's http.ServeMux for routing
	mux := http.NewServeMux()

	mux.HandleFunc("/tasks", handleTasks)
	mux.HandleFunc("/tasks/", handleTaskByID)

	// Wrap mux with logging middleware
	loggedMux := loggingMiddleware(mux)

	// Start the HTTP server
	log.Println("Server starting on http://localhost:8080")
	err = http.ListenAndServe(":8080", loggedMux)
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
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
	rows, err := database.Query("SELECT id, title, description, completed, created_at, updated_at FROM tasks ORDER BY created_at DESC")
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
		err := rows.Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt)
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

	// Insert new task into database
	result, err := database.Exec(
		"INSERT INTO tasks (title, description, completed) VALUES (?, ?, ?)",
		task.Title, task.Description, task.Completed,
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
		"SELECT id, title, description, completed, created_at, updated_at FROM tasks WHERE id = ?",
		id,
	).Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt)

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
	// Extract ID from the URL path
	id, err := extractID(r.URL.Path)
	if err != nil {
		log.Printf("Invalid task ID in URL path %s: %v", r.URL.Path, err)
		http.Error(w, "Invalid task ID", http.StatusBadRequest)
		return
	}

	var task Task
	err = database.QueryRow(
		"SELECT id, title, description, completed, created_at, updated_at FROM tasks WHERE id = ?",
		id,
	).Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		log.Printf("Task not found with ID: %d", id)
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

	// Update the task in database
	result, err := database.Exec(
		"UPDATE tasks SET title = ?, description = ?, completed = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		task.Title, task.Description, task.Completed, id,
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
		log.Printf("Task not found with ID: %d (update attempt)", id)
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	// Retrieve the updated task
	err = database.QueryRow(
		"SELECT id, title, description, completed, created_at, updated_at FROM tasks WHERE id = ?",
		id,
	).Scan(&task.ID, &task.Title, &task.Description, &task.Completed, &task.CreatedAt, &task.UpdatedAt)

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
	// Extract ID from URL path
	id, err := extractID(r.URL.Path)
	if err != nil {
		log.Printf("Invalid task ID in URL path %s: %v", r.URL.Path, err)
		http.Error(w, "Invalid task ID", http.StatusBadRequest)
		return
	}

	result, err := database.Exec("DELETE FROM tasks WHERE id = ?", id)
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
		log.Printf("Task not found with ID: %d (delete attempt)", id)
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	// Return success with no content
	w.WriteHeader(http.StatusNoContent)
}

// extractID is a helper function to extract the task ID from the URL path
// For example: "/tasks/123" -> 123
func extractID(path string) (int, error) {
	// Remove "/tasks/" prefix to get the ID
	parts := strings.Split(strings.TrimPrefix(path, "/tasks/"), "/")
	if len(parts) == 0 {
		return 0, sql.ErrNoRows
	}

	// Convert string ID to integer
	return strconv.Atoi(parts[0])
}
