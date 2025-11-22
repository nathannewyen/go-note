# Go Note API

A simple RESTful API for managing tasks/notes built with Go and SQLite.

## What You Built

This project demonstrates key Go concepts:
- **HTTP server** using the standard `net/http` package
- **SQLite database** integration with SQL queries
- **JSON encoding/decoding** for API requests/responses
- **Struct tags** for JSON serialization
- **Error handling** patterns in Go
- **HTTP routing** and method handling

## Project Structure

```
go-note/
├── main.go              # Complete API implementation
├── notes.db             # SQLite database (created on first run)
└── README.md

../bruno-collections/
└── go-note/             # Bruno API testing files
```

## Running the API

1. Start the server:
```bash
go run main.go
```

2. The server will start on `http://localhost:8080`

## API Endpoints

| Method | Endpoint      | Description          |
|--------|---------------|----------------------|
| GET    | `/tasks`      | Get all tasks        |
| POST   | `/tasks`      | Create a new task    |
| GET    | `/tasks/:id`  | Get a specific task  |
| PUT    | `/tasks/:id`  | Update a task        |
| DELETE | `/tasks/:id`  | Delete a task        |

## Testing with Bruno

1. Open Bruno and import the collection from `../bruno-collections/go-note/`
2. Run the requests in order:
   - Create Task (creates a task)
   - Get All Tasks (lists all tasks)
   - Get Task by ID (gets task with ID 1)
   - Update Task (updates task with ID 1)
   - Delete Task (deletes task with ID 1)

## Testing with curl

Create a task:
```bash
curl -X POST http://localhost:8080/tasks \
  -H "Content-Type: application/json" \
  -d '{"title":"Learn Go","description":"Study Go fundamentals","completed":false}'
```

Get all tasks:
```bash
curl http://localhost:8080/tasks
```

Get task by ID:
```bash
curl http://localhost:8080/tasks/1
```

Update a task:
```bash
curl -X PUT http://localhost:8080/tasks/1 \
  -H "Content-Type: application/json" \
  -d '{"title":"Learn Go - Updated","description":"Study Go fundamentals and concurrency","completed":true}'
```

Delete a task:
```bash
curl -X DELETE http://localhost:8080/tasks/1
```

## Key Go Concepts Demonstrated

### 1. Structs and JSON Tags
```go
type Task struct {
    ID          int       `json:"id"`
    Title       string    `json:"title"`
    Completed   bool      `json:"completed"`
    CreatedAt   time.Time `json:"created_at"`
}
```
The `json:"field_name"` tags tell Go how to convert between JSON and struct fields.

### 2. HTTP Handlers
```go
func handleTasks(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        getTasks(w, r)
    case http.MethodPost:
        createTask(w, r)
    }
}
```
Handlers receive requests and send responses.

### 3. Database Queries
```go
database.Query("SELECT * FROM tasks")           // Multiple rows
database.QueryRow("SELECT * FROM tasks WHERE id = ?", id)  // Single row
database.Exec("INSERT INTO tasks ...")          // Insert/Update/Delete
```

### 4. Error Handling
```go
if err != nil {
    http.Error(w, "Error message", http.StatusInternalServerError)
    log.Println("Error details:", err)
    return
}
```
Go uses explicit error checking instead of exceptions.

### 5. JSON Encoding/Decoding
```go
json.NewDecoder(r.Body).Decode(&task)  // Request → Struct
json.NewEncoder(w).Encode(task)         // Struct → Response
```

## Next Steps to Learn More

1. **Add filtering** - Filter tasks by completed status
2. **Add pagination** - Limit results and add page navigation
3. **Add categories** - Create a categories table and relationships
4. **Add validation** - Use a validation library
5. **Add middleware** - Logging, CORS, authentication
6. **Add tests** - Write unit tests for handlers
7. **Refactor** - Split into separate files (handlers.go, models.go, database.go)

## Common Go Patterns You Learned

- `defer` for cleanup (closing database connections)
- Using `_` to ignore values (like in `import _ "modernc.org/sqlite"`)
- Pointers with `&` and `*` for reference passing
- Error handling with explicit checks
- Package imports and organization
# go-note
