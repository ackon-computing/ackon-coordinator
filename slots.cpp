#include "slots.hpp"

/*
#define task_status_QUEUED 0
#define task_status_FETCHED 1
#define task_status_DONE 2

#define batch_status_RUNNING 0
#define batch_status_DONE 1

typedef struct {
    int batch_id;

    int fetched_count;
    int done_count;
    int of;
    int status;
} batch;

typedef struct {
    batch *batch;
    int n;
    int of;
    json data;
    int status;
} task;
*/

batch* batches = 0;
task*  tasks = 0;

size_t batches_count = 0;
size_t tasks_count = 0;

void init_slots() {
    batches = (batch*)malloc(0);
    tasks = (task*)malloc(0);
    batches_count = 0;
    tasks_count = 0;
}

void new_batch(json data, int of) {
    batches_count++;
    batches = (batch*)realloc(batches, sizeof(batch) * batches_count);
    batch* cb = &(batches[batches_count - 1]);
    cb->batch_id = std::stoi(std::string(data["task"]["task-id"]));
    cb->done_count = 0;
    cb->fetched_count = 0;
    cb->of = of;
    cb->status = batch_status_RUNNING;

    for (int i=0; i<of; i++) {
	tasks_count++;
	tasks = (task*)realloc(tasks, sizeof(task) * tasks_count);
	task* ct = &(tasks[tasks_count - 1]);
	ct->b = cb;
	ct->n = i;
	ct->of = of;
	ct->data = data;
	ct->data["task"]["unsigned"]["index"]["n"] = i;
	ct->status = task_status_QUEUED;
    }
}

json* fetch_task() {
    for (int i=0; i<tasks_count; i++) {
	if (tasks[i].status == task_status_QUEUED) {
	    tasks[i].status = task_status_FETCHED;
	    tasks[i].b->fetched_count++;
	    return &(tasks[i].data);
	}
    }
    return 0;
}
