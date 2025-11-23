package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) {
	var err error
	// Use in-memory database for tests (data is lost after test)
	database, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create users table
	_, err = database.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create users table: %v", err)
	}

	// Create tasks table
	_, err = database.Exec(`
		CREATE TABLE tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			description TEXT,
			completed BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			user_id INTEGER NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create tasks table: %v", err)
	}
}

// teardownTestDB closes the test database
func teardownTestDB() {
	if database != nil {
		database.Close()
	}
}

// createTestUser creates a test user and returns the user ID
func createTestUser(t *testing.T, email, password string) int {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	result, err := database.Exec(
		"INSERT INTO users (email, password) VALUES (?, ?)",
		email, string(hashedPassword),
	)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("Failed to get user ID: %v", err)
	}

	return int(userID)
}

// TestGenerateJWT tests JWT token generation
func TestGenerateJWT(t *testing.T) {
	token, err := generateJWT(1, "test@example.com")
	if err != nil {
		t.Errorf("Failed to generate JWT: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	// Token should have 3 parts separated by dots
	parts := len(bytes.Split([]byte(token), []byte(".")))
	if parts != 3 {
		t.Errorf("Expected 3 parts in JWT, got %d", parts)
	}
}

// TestValidateJWT tests JWT token validation
func TestValidateJWT(t *testing.T) {
	// Generate a valid token
	token, err := generateJWT(1, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	// Validate the token
	claims, err := validateJWT(token)
	if err != nil {
		t.Errorf("Failed to validate JWT: %v", err)
	}

	if claims.UserID != 1 {
		t.Errorf("Expected user ID 1, got %d", claims.UserID)
	}

	if claims.Email != "test@example.com" {
		t.Errorf("Expected email test@example.com, got %s", claims.Email)
	}
}

// TestValidateJWT_Invalid tests validation of invalid tokens
func TestValidateJWT_Invalid(t *testing.T) {
	invalidTokens := []string{
		"invalid.token.here",
		"",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
	}

	for _, token := range invalidTokens {
		_, err := validateJWT(token)
		if err == nil {
			t.Errorf("Expected error for invalid token: %s", token)
		}
	}
}

// TestExtractID tests extracting task ID from URL path
func TestExtractID(t *testing.T) {
	tests := []struct {
		path     string
		expected int
		hasError bool
	}{
		{"/tasks/123", 123, false},
		{"/tasks/1", 1, false},
		{"/tasks/abc", 0, true},
		{"/tasks/", 0, true},
	}

	for _, test := range tests {
		id, err := extractID(test.path)
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for path %s, got none", test.path)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for path %s: %v", test.path, err)
			}
			if id != test.expected {
				t.Errorf("Expected ID %d for path %s, got %d", test.expected, test.path, id)
			}
		}
	}
}

// TestHandleRegister tests user registration
func TestHandleRegister(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	tests := []struct {
		name           string
		requestBody    RegisterRequest
		expectedStatus int
	}{
		{
			name: "Valid registration",
			requestBody: RegisterRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Email already exists",
			requestBody: RegisterRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			expectedStatus: http.StatusConflict,
		},
		{
			name: "Password too short",
			requestBody: RegisterRequest{
				Email:    "new@example.com",
				Password: "123",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Empty email",
			requestBody: RegisterRequest{
				Email:    "",
				Password: "password123",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create request body
			body, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handleRegister(w, req)

			// Check status code
			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}

			// For successful registration, verify response has user data
			if test.expectedStatus == http.StatusCreated {
				var resp UserResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				if err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				if resp.Email != test.requestBody.Email {
					t.Errorf("Expected email %s, got %s", test.requestBody.Email, resp.Email)
				}
			}
		})
	}
}

// TestHandleLogin tests user login
func TestHandleLogin(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	// Create a test user
	email := "test@example.com"
	password := "password123"
	createTestUser(t, email, password)

	tests := []struct {
		name           string
		requestBody    LoginRequest
		expectedStatus int
	}{
		{
			name: "Valid login",
			requestBody: LoginRequest{
				Email:    email,
				Password: password,
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Wrong password",
			requestBody: LoginRequest{
				Email:    email,
				Password: "wrongpassword",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Non-existent user",
			requestBody: LoginRequest{
				Email:    "nonexistent@example.com",
				Password: password,
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create request body
			body, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			handleLogin(w, req)

			// Check status code
			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}

			// For successful login, verify response has token
			if test.expectedStatus == http.StatusOK {
				var resp LoginResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				if err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				if resp.Token == "" {
					t.Error("Expected token in response, got empty string")
				}
				if resp.User.Email != email {
					t.Errorf("Expected email %s, got %s", email, resp.User.Email)
				}
			}
		})
	}
}

// TestCreateTask tests task creation
func TestCreateTask(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	// Create test user and get token
	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	tests := []struct {
		name           string
		requestBody    Task
		useAuth        bool
		expectedStatus int
	}{
		{
			name: "Valid task creation",
			requestBody: Task{
				Title:       "Test Task",
				Description: "Test Description",
				Completed:   false,
			},
			useAuth:        true,
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Empty title",
			requestBody: Task{
				Title:       "",
				Description: "Test Description",
				Completed:   false,
			},
			useAuth:        true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "No authentication",
			requestBody: Task{
				Title:       "Test Task",
				Description: "Test Description",
				Completed:   false,
			},
			useAuth:        false,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create request body
			body, _ := json.Marshal(test.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/tasks", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			if test.useAuth {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler through middleware
			authMiddleware(handleTasks)(w, req)

			// Check status code
			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", test.expectedStatus, w.Code, w.Body.String())
			}

			// For successful creation, verify response has task data
			if test.expectedStatus == http.StatusCreated {
				var resp Task
				err := json.NewDecoder(w.Body).Decode(&resp)
				if err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				if resp.Title != test.requestBody.Title {
					t.Errorf("Expected title %s, got %s", test.requestBody.Title, resp.Title)
				}
				if resp.UserID != userID {
					t.Errorf("Expected user ID %d, got %d", userID, resp.UserID)
				}
			}
		})
	}
}

// TestGetTasks tests retrieving all tasks
func TestGetTasks(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	// Create test user and get token
	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	// Create some test tasks
	database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Task 1", "Description 1", false, userID)
	database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Task 2", "Description 2", true, userID)

	// Create another user with their own task
	otherUserID := createTestUser(t, "other@example.com", "password123")
	database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Other Task", "Other Description", false, otherUserID)

	// Make request
	req := httptest.NewRequest(http.MethodGet, "/tasks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Call handler through middleware
	authMiddleware(handleTasks)(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Decode response
	var tasks []Task
	err := json.NewDecoder(w.Body).Decode(&tasks)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should only get tasks for authenticated user
	if len(tasks) != 2 {
		t.Errorf("Expected 2 tasks, got %d", len(tasks))
	}

	// Verify all tasks belong to the authenticated user
	for _, task := range tasks {
		if task.UserID != userID {
			t.Errorf("Expected user ID %d, got %d", userID, task.UserID)
		}
	}
}

// TestUpdateTask tests updating a task
func TestUpdateTask(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	// Create test user and get token
	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	// Create a test task
	result, _ := database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Original Title", "Original Description", false, userID)
	taskID, _ := result.LastInsertId()

	// Update request
	updateData := Task{
		Title:       "Updated Title",
		Description: "Updated Description",
		Completed:   true,
	}

	body, _ := json.Marshal(updateData)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tasks/%d", taskID), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Call handler through middleware
	authMiddleware(handleTaskByID)(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Decode response
	var resp Task
	err := json.NewDecoder(w.Body).Decode(&resp)
	if err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify update
	if resp.Title != updateData.Title {
		t.Errorf("Expected title %s, got %s", updateData.Title, resp.Title)
	}
	if resp.Completed != updateData.Completed {
		t.Errorf("Expected completed %v, got %v", updateData.Completed, resp.Completed)
	}
}

// TestDeleteTask tests deleting a task
func TestDeleteTask(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	// Create test user and get token
	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	// Create a test task
	result, _ := database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Task to Delete", "Description", false, userID)
	taskID, _ := result.LastInsertId()

	// Delete request
	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/tasks/%d", taskID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Call handler through middleware
	authMiddleware(handleTaskByID)(w, req)

	// Check status code
	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify task is deleted from database
	var count int
	database.QueryRow("SELECT COUNT(*) FROM tasks WHERE id = ?", taskID).Scan(&count)
	if count != 0 {
		t.Error("Task was not deleted from database")
	}
}

// TestAuthMiddleware tests the authentication middleware
func TestAuthMiddleware(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	// Create test user and get token
	userID := createTestUser(t, "test@example.com", "password123")
	validToken, _ := generateJWT(userID, "test@example.com")

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "Valid token",
			authHeader:     "Bearer " + validToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing Authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid token format (no Bearer)",
			authHeader:     validToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid token",
			authHeader:     "Bearer invalid.token.here",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	// Dummy handler that returns 200 if middleware passes
	dummyHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if test.authHeader != "" {
				req.Header.Set("Authorization", test.authHeader)
			}

			w := httptest.NewRecorder()

			// Call middleware with dummy handler
			authMiddleware(dummyHandler)(w, req)

			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}
		})
	}
}

// TestGetTask tests retrieving a single task by ID
func TestGetTask(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	// Create test user and get token
	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	// Create another user
	otherUserID := createTestUser(t, "other@example.com", "password123")

	// Create a test task for the first user
	result, _ := database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"My Task", "My Description", false, userID)
	taskID, _ := result.LastInsertId()

	// Create a task for the other user
	otherResult, _ := database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Other Task", "Other Description", false, otherUserID)
	otherTaskID, _ := otherResult.LastInsertId()

	tests := []struct {
		name           string
		taskID         int64
		expectedStatus int
		checkResponse  bool
	}{
		{
			name:           "Get own task",
			taskID:         taskID,
			expectedStatus: http.StatusOK,
			checkResponse:  true,
		},
		{
			name:           "Get non-existent task",
			taskID:         9999,
			expectedStatus: http.StatusNotFound,
			checkResponse:  false,
		},
		{
			name:           "Get other user's task",
			taskID:         otherTaskID,
			expectedStatus: http.StatusNotFound,
			checkResponse:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/tasks/%d", test.taskID), nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			authMiddleware(handleTaskByID)(w, req)

			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}

			if test.checkResponse {
				var resp Task
				err := json.NewDecoder(w.Body).Decode(&resp)
				if err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				if resp.Title != "My Task" {
					t.Errorf("Expected title 'My Task', got %s", resp.Title)
				}
			}
		})
	}
}

// TestGetTask_InvalidID tests getting a task with invalid ID
func TestGetTask_InvalidID(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	req := httptest.NewRequest(http.MethodGet, "/tasks/invalid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestUpdateTask_NotFound tests updating non-existent task
func TestUpdateTask_NotFound(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	updateData := Task{
		Title:       "Updated",
		Description: "Updated",
		Completed:   true,
	}

	body, _ := json.Marshal(updateData)
	req := httptest.NewRequest(http.MethodPut, "/tasks/9999", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestUpdateTask_InvalidID tests updating with invalid ID
func TestUpdateTask_InvalidID(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	updateData := Task{Title: "Updated", Description: "Updated", Completed: true}
	body, _ := json.Marshal(updateData)

	req := httptest.NewRequest(http.MethodPut, "/tasks/invalid", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestUpdateTask_EmptyTitle tests updating with empty title
func TestUpdateTask_EmptyTitle(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	result, _ := database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Original", "Original", false, userID)
	taskID, _ := result.LastInsertId()

	updateData := Task{Title: "", Description: "Updated", Completed: true}
	body, _ := json.Marshal(updateData)

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tasks/%d", taskID), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestUpdateTask_InvalidJSON tests updating with invalid JSON
func TestUpdateTask_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	result, _ := database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Original", "Original", false, userID)
	taskID, _ := result.LastInsertId()

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/tasks/%d", taskID), bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestDeleteTask_NotFound tests deleting non-existent task
func TestDeleteTask_NotFound(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	req := httptest.NewRequest(http.MethodDelete, "/tasks/9999", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestDeleteTask_InvalidID tests deleting with invalid ID
func TestDeleteTask_InvalidID(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	req := httptest.NewRequest(http.MethodDelete, "/tasks/invalid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestDeleteTask_OtherUser tests deleting another user's task
func TestDeleteTask_OtherUser(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	// Create another user and their task
	otherUserID := createTestUser(t, "other@example.com", "password123")
	result, _ := database.Exec("INSERT INTO tasks (title, description, completed, user_id) VALUES (?, ?, ?, ?)",
		"Other Task", "Description", false, otherUserID)
	otherTaskID, _ := result.LastInsertId()

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/tasks/%d", otherTaskID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	authMiddleware(handleTaskByID)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}

	// Verify task still exists
	var count int
	database.QueryRow("SELECT COUNT(*) FROM tasks WHERE id = ?", otherTaskID).Scan(&count)
	if count != 1 {
		t.Error("Task was deleted when it shouldn't have been")
	}
}

// TestHandleTasks_MethodNotAllowed tests unsupported HTTP methods
func TestHandleTasks_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	methods := []string{http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/tasks", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			authMiddleware(handleTasks)(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d for method %s, got %d", http.StatusMethodNotAllowed, method, w.Code)
			}
		})
	}
}

// TestHandleTaskByID_MethodNotAllowed tests unsupported HTTP methods on task by ID
func TestHandleTaskByID_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	methods := []string{http.MethodPost, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/tasks/1", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			authMiddleware(handleTaskByID)(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d for method %s, got %d", http.StatusMethodNotAllowed, method, w.Code)
			}
		})
	}
}

// TestHandleRegister_InvalidJSON tests registration with invalid JSON
func TestHandleRegister_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestHandleRegister_MethodNotAllowed tests non-POST methods on register
func TestHandleRegister_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/auth/register", nil)
			w := httptest.NewRecorder()

			handleRegister(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d for method %s, got %d", http.StatusMethodNotAllowed, method, w.Code)
			}
		})
	}
}

// TestHandleLogin_InvalidJSON tests login with invalid JSON
func TestHandleLogin_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestHandleLogin_MethodNotAllowed tests non-POST methods on login
func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/auth/login", nil)
			w := httptest.NewRecorder()

			handleLogin(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d for method %s, got %d", http.StatusMethodNotAllowed, method, w.Code)
			}
		})
	}
}

// TestCreateTask_InvalidJSON tests creating task with invalid JSON
func TestCreateTask_InvalidJSON(t *testing.T) {
	setupTestDB(t)
	defer teardownTestDB()

	userID := createTestUser(t, "test@example.com", "password123")
	token, _ := generateJWT(userID, "test@example.com")

	req := httptest.NewRequest(http.MethodPost, "/tasks", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authMiddleware(handleTasks)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// TestGetStatusText tests status text generation
func TestGetStatusText(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{200, "SUCCESS"},
		{201, "SUCCESS"},
		{299, "SUCCESS"},
		{400, "CLIENT_ERROR"},
		{404, "CLIENT_ERROR"},
		{499, "CLIENT_ERROR"},
		{500, "SERVER_ERROR"},
		{503, "SERVER_ERROR"},
		{100, "UNKNOWN"},
		{300, "UNKNOWN"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Code_%d", test.code), func(t *testing.T) {
			result := getStatusText(test.code)
			if result != test.expected {
				t.Errorf("Expected %s for code %d, got %s", test.expected, test.code, result)
			}
		})
	}
}

// TestLoggingMiddleware tests request logging
func TestLoggingMiddleware(t *testing.T) {
	// Create a simple handler that returns 200
	successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create a handler that returns 404
	notFoundHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	// Create a handler that returns 500
	errorHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Error"))
	})

	tests := []struct {
		name           string
		handler        http.Handler
		expectedStatus int
	}{
		{
			name:           "Success response",
			handler:        successHandler,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Not found response",
			handler:        notFoundHandler,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Error response",
			handler:        errorHandler,
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Wrap handler with logging middleware
			loggedHandler := loggingMiddleware(test.handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			// Call handler
			loggedHandler.ServeHTTP(w, req)

			// Verify status code
			if w.Code != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, w.Code)
			}
		})
	}
}

// TestResponseWriter tests the custom response writer
func TestResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Test WriteHeader
	rw.WriteHeader(http.StatusCreated)
	if rw.statusCode != http.StatusCreated {
		t.Errorf("Expected status code %d, got %d", http.StatusCreated, rw.statusCode)
	}

	if w.Code != http.StatusCreated {
		t.Errorf("Expected response status %d, got %d", http.StatusCreated, w.Code)
	}
}
