package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"winopsguard/internal/model"
)

type Request struct {
	ID         string         `json:"id"`
	Payload    model.AIRequest `json:"payload"`
	EnqueuedAt time.Time      `json:"enqueued_at"`
}

type Queue struct {
	dir string
}

func NewQueue(dir string) *Queue {
	if dir == "" {
		dir = "queue"
	}
	_ = os.MkdirAll(dir, 0755)
	return &Queue{dir: dir}
}

func (q *Queue) Enqueue(payload model.AIRequest) *Request {
	req := &Request{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Payload:    payload,
		EnqueuedAt: time.Now().UTC(),
	}
	data, _ := json.MarshalIndent(req, "", "  ")
	_ = os.WriteFile(q.path(req.ID), data, 0644)
	return req
}

func (q *Queue) MarkSent(id string) {
	_ = os.Remove(q.path(id))
}

func (q *Queue) List() ([]Request, error) {
	files, err := filepath.Glob(filepath.Join(q.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var res []Request
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r Request
		if err := json.Unmarshal(data, &r); err == nil {
			res = append(res, r)
		}
	}
	return res, nil
}

func (q *Queue) path(id string) string {
	return filepath.Join(q.dir, id+".json")
}
