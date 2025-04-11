package queue

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
)


func TestQueue_WorkerProcessing(t *testing.T) {
	var mu sync.Mutex
	var calledJobs []string

	logger := log.NewNopLogger()

	// Create the queue
	q := NewQueue("test-queue")

	// Define jobs
	jobs := []Job{
		{
			Name: "job1",
			Action: func() error {
				mu.Lock()
				defer mu.Unlock()
				calledJobs = append(calledJobs, "job1")
				return nil
			},
		},
		{
			Name: "job2",
			Action: func() error {
				mu.Lock()
				defer mu.Unlock()
				calledJobs = append(calledJobs, "job2")
				return errors.New("job2 failed")
			},
		},
		{
			Name: "job3",
			Action: func() error {
				mu.Lock()
				defer mu.Unlock()
				calledJobs = append(calledJobs, "job3")
				return nil
			},
		},
	}

	// Add jobs to queue
	q.AddJobs(jobs, logger)

	// Create a worker
	worker := NewWorker(q, logger)

	// Run worker in goroutine so we can time out test
	done := make(chan bool)
	go func() {
		done <- worker.DoWork()
	}()

	// Wait a bit to ensure jobs are processed
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not complete in time")
	}

	// Check that all jobs were attempted
	mu.Lock()
	defer mu.Unlock()

	if len(calledJobs) != 3 {
		t.Errorf("expected 3 jobs to be called, got %d", len(calledJobs))
	}
}
