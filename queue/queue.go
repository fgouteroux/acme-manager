package queue

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// Queue holds name, list of jobs and context with cancel.
type Queue struct {
	name   string
	jobs   chan Job
	ctx    context.Context
	cancel context.CancelFunc
}

// Job - holds logic to perform some operations during queue execution.
type Job struct {
	Name   string
	Action func() error
}

// Worker responsible for queue serving.
type Worker struct {
	Queue  *Queue
	Logger log.Logger
}

// NewQueue instantiates new queue.
func NewQueue(name string) *Queue {
	ctx, cancel := context.WithCancel(context.Background())

	return &Queue{
		jobs:   make(chan Job),
		name:   name,
		ctx:    ctx,
		cancel: cancel,
	}
}

// AddJobs adds jobs to the queue and cancels channel.
func (q *Queue) AddJobs(jobs []Job, logger log.Logger) {
	var wg sync.WaitGroup
	wg.Add(len(jobs))

	for _, job := range jobs {
		go func(job Job) {
			q.AddJob(job, logger)
			wg.Done()
		}(job)
	}

	go func() {
		wg.Wait()
		q.cancel()
	}()

}

// AddJob sends job to the channel.
func (q *Queue) AddJob(job Job, logger log.Logger) {
	_ = level.Debug(logger).Log("msg", fmt.Sprintf("Adding job '%s' to queue '%s", job.Name, q.name))
	q.jobs <- job
}

// Run performs job execution.
func (j Job) Run(logger log.Logger) error {
	_ = level.Debug(logger).Log("msg", fmt.Sprintf("Job running: %s", j.Name))

	err := j.Action()
	if err != nil {
		return err
	}

	_ = level.Debug(logger).Log("msg", fmt.Sprintf("Job ending: %s", j.Name))

	return nil
}

// NewWorker initialises new Worker.
func NewWorker(queue *Queue, logger log.Logger) *Worker {
	return &Worker{
		Queue:  queue,
		Logger: logger,
	}
}

// DoWork processes jobs from the queue (jobs channel).
func (w *Worker) DoWork() bool {
	for {
		select {
		// if context was canceled.
		case <-w.Queue.ctx.Done():
			_ = level.Debug(w.Logger).Log("msg", fmt.Sprintf("Work done in queue %s: %s!", w.Queue.name, w.Queue.ctx.Err()))
			return true
		// if job received.
		case job := <-w.Queue.jobs:
			err := job.Run(w.Logger)
			if err != nil {
				_ = level.Error(w.Logger).Log("err", err)
				continue
			}
		}
	}
}
